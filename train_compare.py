"""
Train and compare models for VPN traffic classification.
Features (10):
  [0] packet_length   – raw IP payload length (1-1500)
  [1] entropy         – Shannon entropy of first 128 bytes (0-8)
  [2] compression     – 1.0 if entropy > 7.5, else 0.5 (encrypted vs compressible)
  [3] mean_byte       – mean of first 128 payload bytes
  [4] stddev_byte     – std of first 128 payload bytes
  [5] num_ciphers     – TLS ClientHello: number of cipher suites (0 if not TLS CH)
  [6] num_extensions  – TLS ClientHello: number of extensions (0 if not TLS CH)
  [7] has_alpn        – TLS ClientHello: ALPN extension present (0/1)
  [8] alpn_h2         – TLS ClientHello: h2 in ALPN (0/1)
  [9] has_grease      – TLS ClientHello: GREASE value in extensions (0/1)
Output: probability that packet is VPN traffic (0.0 – 1.0)
"""
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import xgboost as xgb
import lightgbm as lgb
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx
import warnings
warnings.filterwarnings("ignore")

np.random.seed(42)

N = 20_000   # larger dataset for 10-feature model

# ---------------------------------------------------------------------------
# Synthetic dataset — three traffic types mixed into VPN vs non-VPN
# ---------------------------------------------------------------------------
# VPN traffic types:
#   A) Post-handshake encrypted data (high entropy, no TLS CH features)
#   B) OpenVPN TCP ClientHello (TLS CH, no GREASE, no ALPN, ~10 ciphers, ~7 ext)
#   C) WireGuard / UDP VPN (high entropy, very uniform mean/std)
#
# Normal traffic types:
#   D) HTTPS TLS application data (high entropy, no TLS CH features)
#   E) Browser TLS ClientHello (many ciphers, many ext, has GREASE + ALPN)
#   F) Plain HTTP / DNS / other (low entropy, varied sizes)

def make_vpn_encrypted(n):
    """Post-handshake VPN tunnel data: high entropy, large packets, no CH features."""
    length      = np.random.normal(1300, 150, n).clip(200, 1500)
    entropy     = np.random.normal(7.85, 0.1, n).clip(7.5, 8.0)
    compression = np.ones(n)
    mean_byte   = np.random.normal(128, 15, n).clip(0, 255)
    stddev_byte = np.random.normal(82, 5, n).clip(60, 100)
    # No TLS ClientHello on these packets
    num_ciphers = np.zeros(n)
    num_ext     = np.zeros(n)
    has_alpn    = np.zeros(n)
    alpn_h2     = np.zeros(n)
    has_grease  = np.zeros(n)
    return np.column_stack([length, entropy, compression, mean_byte, stddev_byte,
                             num_ciphers, num_ext, has_alpn, alpn_h2, has_grease])

def make_vpn_tls_clienthello(n):
    """OpenVPN / non-browser VPN tool TLS ClientHello: no GREASE, no ALPN, fewer ciphers."""
    length      = np.random.normal(350, 80, n).clip(200, 600)
    entropy     = np.random.normal(5.2, 0.8, n).clip(3.0, 7.5)
    compression = np.full(n, 0.5)
    mean_byte   = np.random.normal(100, 30, n).clip(0, 255)
    stddev_byte = np.random.normal(65, 15, n).clip(10, 100)
    # TLS CH present, no GREASE, no ALPN, fewer ciphers
    num_ciphers = np.random.randint(4, 12, n).astype(float)
    num_ext     = np.random.randint(4, 9, n).astype(float)
    has_alpn    = np.zeros(n)    # VPN tools don't use ALPN
    alpn_h2     = np.zeros(n)
    has_grease  = np.zeros(n)    # VPN tools don't use GREASE
    return np.column_stack([length, entropy, compression, mean_byte, stddev_byte,
                             num_ciphers, num_ext, has_alpn, alpn_h2, has_grease])

def make_normal_https_data(n):
    """Browser HTTPS application data: high entropy (encrypted), varied sizes."""
    pool = np.concatenate([
        np.random.normal(200, 100, n).clip(64, 500),
        np.random.normal(900, 300, n).clip(400, 1460),
        np.random.normal(1400, 60, n).clip(1000, 1460),
    ])
    length = np.random.choice(pool, n, replace=False)
    entropy     = np.random.normal(7.7, 0.3, n).clip(6.5, 8.0)
    compression = np.ones(n)
    mean_byte   = np.random.normal(127, 25, n).clip(0, 255)
    stddev_byte = np.random.normal(80, 10, n).clip(50, 110)
    num_ciphers = np.zeros(n)
    num_ext     = np.zeros(n)
    has_alpn    = np.zeros(n)
    alpn_h2     = np.zeros(n)
    has_grease  = np.zeros(n)
    return np.column_stack([length, entropy, compression, mean_byte, stddev_byte,
                             num_ciphers, num_ext, has_alpn, alpn_h2, has_grease])

def make_browser_clienthello(n):
    """Browser TLS ClientHello: many ciphers, many ext, GREASE + ALPN always present."""
    length      = np.random.normal(512, 100, n).clip(300, 800)
    entropy     = np.random.normal(4.8, 0.9, n).clip(3.0, 7.0)
    compression = np.full(n, 0.5)
    mean_byte   = np.random.normal(95, 35, n).clip(0, 255)
    stddev_byte = np.random.normal(60, 15, n).clip(10, 100)
    # Browsers: 17-30 cipher suites, 12-20 extensions, always GREASE + ALPN
    num_ciphers = np.random.randint(17, 30, n).astype(float)
    num_ext     = np.random.randint(12, 20, n).astype(float)
    has_alpn    = np.ones(n)
    alpn_h2     = np.random.choice([0.0, 1.0], n, p=[0.1, 0.9])
    has_grease  = np.ones(n)
    return np.column_stack([length, entropy, compression, mean_byte, stddev_byte,
                             num_ciphers, num_ext, has_alpn, alpn_h2, has_grease])

def make_normal_other(n):
    """Plain HTTP, DNS, other low-entropy traffic."""
    length      = np.random.exponential(300, n).clip(40, 1000)
    entropy     = np.random.normal(4.5, 1.5, n).clip(1.0, 7.0)
    compression = np.random.uniform(0.3, 0.7, n)
    mean_byte   = np.random.normal(85, 45, n).clip(0, 255)
    stddev_byte = np.random.normal(45, 20, n).clip(5, 100)
    num_ciphers = np.zeros(n)
    num_ext     = np.zeros(n)
    has_alpn    = np.zeros(n)
    alpn_h2     = np.zeros(n)
    has_grease  = np.zeros(n)
    return np.column_stack([length, entropy, compression, mean_byte, stddev_byte,
                             num_ciphers, num_ext, has_alpn, alpn_h2, has_grease])

# Build balanced dataset — N/2 VPN, N/2 normal
half = N // 2
vpn_X = np.vstack([
    make_vpn_encrypted(half * 3 // 5),           # 60%: post-handshake encrypted data
    make_vpn_tls_clienthello(half * 2 // 5),     # 40%: TLS ClientHello packets
])
normal_X = np.vstack([
    make_normal_https_data(half * 2 // 5),        # 40%: HTTPS application data
    make_browser_clienthello(half * 2 // 5),      # 40%: browser TLS ClientHello
    make_normal_other(half - (half * 2 // 5) * 2),# 20%: other traffic
])

X = np.vstack([vpn_X, normal_X]).astype(np.float32)
y = np.array([1] * len(vpn_X) + [0] * len(normal_X))

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Dataset: {len(X)} samples, {X.shape[1]} features")
print(f"VPN: {len(vpn_X)}  Normal: {len(normal_X)}")
print(f"Train: {len(X_train)}  Test: {len(X_test)}\n")

# ---------------------------------------------------------------------------
# Models to compare
# ---------------------------------------------------------------------------
models = {
    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000)),
    ]),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=12, n_jobs=-1
    ),
    "Gradient Boosting": GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.05
    ),
    "XGBoost": xgb.XGBClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.05,
        use_label_encoder=False, eval_metric="logloss", verbosity=0
    ),
    "LightGBM": lgb.LGBMClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.05, verbose=-1
    ),
    "MLP (Neural Net)": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", MLPClassifier(
            hidden_layer_sizes=(64, 32, 16), max_iter=500,
            activation="relu", random_state=42
        )),
    ]),
}

# ---------------------------------------------------------------------------
# Train + evaluate
# ---------------------------------------------------------------------------
results = {}
col_w = 22

header = (
    f"{'Model':<{col_w}} {'Acc':>6} {'Prec':>6} {'Rec':>6} "
    f"{'F1':>6} {'AUC':>6} {'TN':>5} {'FP':>5} {'FN':>5} {'TP':>5}"
)
print(header)
print("-" * len(header))

best_model = None
best_auc   = 0.0
best_name  = ""

for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    results[name] = dict(acc=acc, prec=prec, rec=rec, f1=f1, auc=auc)
    print(
        f"{name:<{col_w}} {acc:>6.3f} {prec:>6.3f} {rec:>6.3f} "
        f"{f1:>6.3f} {auc:>6.3f} {tn:>5} {fp:>5} {fn:>5} {tp:>5}"
    )

    if auc > best_auc:
        best_auc   = auc
        best_model = model
        best_name  = name

# ---------------------------------------------------------------------------
# Export best model to ONNX (10 features)
# ---------------------------------------------------------------------------
print(f"\nBest model: {best_name} (AUC={best_auc:.4f})")

# LightGBM exports in seq(map) format incompatible with our Rust tensor reader.
# Pick the best skl2onnx-compatible model (GradientBoosting, RandomForest, etc.)
ONNX_SKIP = {"LightGBM"}
export_auc, export_model, export_name = 0.0, None, ""
for name, model in models.items():
    if name in ONNX_SKIP: continue
    a = results[name]["auc"]
    if a > export_auc:
        export_auc, export_model, export_name = a, model, name

if export_name != best_name:
    print(f"(Using {export_name} for ONNX export — AUC {export_auc:.4f} vs {best_auc:.4f})")

print("Exporting to model.onnx (10 features) ...")
initial_type = [("float_input", FloatTensorType([None, 10]))]
onnx_model   = convert_sklearn(
    export_model,
    initial_types=initial_type,
    options={"zipmap": False},
    target_opset=17,
)
onnx.save(onnx_model, "model.onnx")

import onnxruntime as rt
sess    = rt.InferenceSession("model.onnx")
in_name = sess.get_inputs()[0].name
outputs = sess.get_outputs()
print(f"ONNX inputs:  {in_name} shape={sess.get_inputs()[0].shape}")
for i, o in enumerate(outputs):
    print(f"ONNX output[{i}]: name={o.name}  shape={o.shape}  type={o.type}")

sample = X_test[:3].astype(np.float32)
label_preds, prob_preds = sess.run([outputs[0].name, outputs[1].name], {in_name: sample})
print(f"\nLabels:        {label_preds}")
print(f"Probabilities: {prob_preds}")
print(f"VPN score (col 1): {prob_preds[:, 1]}  — this is what Rust checks > 0.5")
print("\nDone. model.onnx ready for deployment.")
