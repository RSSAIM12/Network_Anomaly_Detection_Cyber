

# 1) Imports
import numpy as np
import pandas as pd
import joblib
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tensorflow.keras import layers, models
import tensorflow as tf

# 2) Feature schema (17 features used elsewhere)
FEATURE_COLS = [
    "pkt_count","byte_count","avg_pkt_len","pkt_rate","unique_src","unique_dst","unique_pairs",
    "tcp_count","udp_count","icmp_count","syn_count","rst_count","fin_count",
    "dst_port_entropy","src_port_entropy","iat_mean","iat_std"
]

# 3) Option : charger un CSV fourni par l'utilisateur (avec les colonnes FEATURE_COLS + 'label')
# Si tu as un fichier labeled_windows.csv upload via Colab file picker, il sera utilisé.
uploaded_files = os.listdir()
if "labeled_windows.csv" in uploaded_files:
    print("Using uploaded labeled_windows.csv")
    df_all = pd.read_csv("labeled_windows.csv")
else:
    print("No labeled CSV found — generating synthetic baseline dataset (recommended: replace with real data)")
    # 4) Génération synthétique de base (Normal + attaques)
    rng = np.random.RandomState(42)
    n_norm = 2000
    n_per_attack = 800

    # Normal traffic (baseline)
    normal = pd.DataFrame({
        "pkt_count": rng.poisson(8, n_norm),
        "byte_count": rng.normal(600, 80, n_norm).clip(0),
        "avg_pkt_len": rng.normal(70, 8, n_norm).clip(1),
        "pkt_rate": rng.normal(8, 2, n_norm).clip(0),
        "unique_src": rng.randint(1,4,n_norm),
        "unique_dst": rng.randint(1,4,n_norm),
        "unique_pairs": rng.randint(1,6,n_norm),
        "tcp_count": rng.randint(0,8,n_norm),
        "udp_count": rng.randint(0,6,n_norm),
        "icmp_count": rng.randint(0,2,n_norm),
        "syn_count": rng.binomial(1, 0.05, n_norm),
        "rst_count": rng.binomial(1, 0.01, n_norm),
        "fin_count": rng.binomial(1, 0.02, n_norm),
        "dst_port_entropy": rng.random(n_norm)*1.5,
        "src_port_entropy": rng.random(n_norm)*1.5,
        "iat_mean": rng.exponential(0.1, n_norm),
        "iat_std": rng.random(n_norm)*0.1,
    })
    normal["label"] = "NORMAL"

    # DDoS: Very high pkt_rate, many packets, many unique_src (botnet), dst_port_entropy low (target port)
    ddos = pd.DataFrame({
        "pkt_count": rng.poisson(200, n_per_attack),
        "byte_count": rng.normal(30000, 5000, n_per_attack).clip(0),
        "avg_pkt_len": rng.normal(150,20,n_per_attack).clip(1),
        "pkt_rate": rng.normal(200,40,n_per_attack).clip(0),
        "unique_src": rng.randint(50,300,n_per_attack),
        "unique_dst": rng.randint(1,3,n_per_attack),
        "unique_pairs": rng.randint(50,300,n_per_attack),
        "tcp_count": rng.randint(100,200,n_per_attack),
        "udp_count": rng.randint(0,50,n_per_attack),
        "icmp_count": rng.randint(0,10,n_per_attack),
        "syn_count": rng.binomial(1,0.6,n_per_attack)*rng.randint(100,200,n_per_attack),
        "rst_count": rng.randint(0,10,n_per_attack),
        "fin_count": rng.randint(0,10,n_per_attack),
        "dst_port_entropy": rng.random(n_per_attack)*0.5,
        "src_port_entropy": rng.random(n_per_attack)*2.0,
        "iat_mean": rng.exponential(0.001, n_per_attack),
        "iat_std": rng.random(n_per_attack)*0.01,
    })
    ddos["label"]="DDoS"

    # SYN-FLOOD: high pkt_rate, extremely high syn_count proportion
    syn = pd.DataFrame({
        "pkt_count": rng.poisson(150, n_per_attack),
        "byte_count": rng.normal(20000,3000,n_per_attack).clip(0),
        "avg_pkt_len": rng.normal(130,15,n_per_attack).clip(1),
        "pkt_rate": rng.normal(150,30,n_per_attack).clip(0),
        "unique_src": rng.randint(10,200,n_per_attack),
        "unique_dst": rng.randint(1,4,n_per_attack),
        "unique_pairs": rng.randint(10,200,n_per_attack),
        "tcp_count": rng.randint(120,200,n_per_attack),
        "udp_count": rng.randint(0,20,n_per_attack),
        "icmp_count": rng.randint(0,5,n_per_attack),
        "syn_count": (rng.randint(100,200,n_per_attack)),
        "rst_count": rng.randint(0,5,n_per_attack),
        "fin_count": rng.randint(0,5,n_per_attack),
        "dst_port_entropy": rng.random(n_per_attack)*0.6,
        "src_port_entropy": rng.random(n_per_attack)*2.0,
        "iat_mean": rng.exponential(0.002, n_per_attack),
        "iat_std": rng.random(n_per_attack)*0.02,
    })
    syn["label"]="SYN-FLOOD"

    # UDP-FLOOD: high pkt_rate and mostly UDP
    udp = pd.DataFrame({
        "pkt_count": rng.poisson(180, n_per_attack),
        "byte_count": rng.normal(25000,4000,n_per_attack).clip(0),
        "avg_pkt_len": rng.normal(140,18,n_per_attack).clip(1),
        "pkt_rate": rng.normal(180,30,n_per_attack).clip(0),
        "unique_src": rng.randint(20,200,n_per_attack),
        "unique_dst": rng.randint(1,6,n_per_attack),
        "unique_pairs": rng.randint(20,200,n_per_attack),
        "tcp_count": rng.randint(0,50,n_per_attack),
        "udp_count": rng.randint(150,250,n_per_attack),
        "icmp_count": rng.randint(0,5,n_per_attack),
        "syn_count": rng.randint(0,10,n_per_attack),
        "rst_count": rng.randint(0,10,n_per_attack),
        "fin_count": rng.randint(0,10,n_per_attack),
        "dst_port_entropy": rng.random(n_per_attack)*1.0,
        "src_port_entropy": rng.random(n_per_attack)*2.0,
        "iat_mean": rng.exponential(0.0015, n_per_attack),
        "iat_std": rng.random(n_per_attack)*0.015,
    })
    udp["label"]="UDP-FLOOD"

    # PORT-SCAN: moderate pkt_rate but low dst_port_entropy, many unique dst ports sequence
    scan = pd.DataFrame({
        "pkt_count": rng.poisson(40, n_per_attack),
        "byte_count": rng.normal(2000,400,n_per_attack).clip(0),
        "avg_pkt_len": rng.normal(60,8,n_per_attack).clip(1),
        "pkt_rate": rng.normal(40,8,n_per_attack).clip(0),
        "unique_src": rng.randint(1,10,n_per_attack),
        "unique_dst": rng.randint(1,10,n_per_attack),
        "unique_pairs": rng.randint(1,30,n_per_attack),
        "tcp_count": rng.randint(30,50,n_per_attack),
        "udp_count": rng.randint(0,10,n_per_attack),
        "icmp_count": rng.randint(0,5,n_per_attack),
        "syn_count": rng.randint(10,40,n_per_attack),
        "rst_count": rng.randint(0,10,n_per_attack),
        "fin_count": rng.randint(0,5,n_per_attack),
        "dst_port_entropy": rng.random(n_per_attack)*0.8,
        "src_port_entropy": rng.random(n_per_attack)*1.0,
        "iat_mean": rng.exponential(0.01, n_per_attack),
        "iat_std": rng.random(n_per_attack)*0.05,
    })
    scan["label"]="PORT-SCAN"

    # MALWARE-LIKE: bursts, medium pkt_rate, odd port entropy, irregular iat
    malware = pd.DataFrame({
        "pkt_count": rng.poisson(60, n_per_attack),
        "byte_count": rng.normal(6000,1500,n_per_attack).clip(0),
        "avg_pkt_len": rng.normal(100,25,n_per_attack).clip(1),
        "pkt_rate": rng.normal(60,20,n_per_attack).clip(0),
        "unique_src": rng.randint(1,10,n_per_attack),
        "unique_dst": rng.randint(1,10,n_per_attack),
        "unique_pairs": rng.randint(1,40,n_per_attack),
        "tcp_count": rng.randint(30,60,n_per_attack),
        "udp_count": rng.randint(0,20,n_per_attack),
        "icmp_count": rng.randint(0,10,n_per_attack),
        "syn_count": rng.randint(0,30,n_per_attack),
        "rst_count": rng.randint(0,5,n_per_attack),
        "fin_count": rng.randint(0,5,n_per_attack),
        "dst_port_entropy": rng.random(n_per_attack)*1.5,
        "src_port_entropy": rng.random(n_per_attack)*1.5,
        "iat_mean": rng.exponential(0.005, n_per_attack),
        "iat_std": rng.random(n_per_attack)*0.03,
    })
    malware["label"]="MALWARE"

    # NOISE / VM broadcast / ARP: low pkt_count but unusual patterns (we treat as separate class)
    noise = pd.DataFrame({
        "pkt_count": rng.poisson(3, n_per_attack),
        "byte_count": rng.normal(200,50,n_per_attack).clip(0),
        "avg_pkt_len": rng.normal(70,10,n_per_attack).clip(1),
        "pkt_rate": rng.normal(3,1,n_per_attack).clip(0),
        "unique_src": rng.randint(1,3,n_per_attack),
        "unique_dst": rng.randint(1,3,n_per_attack),
        "unique_pairs": rng.randint(1,3,n_per_attack),
        "tcp_count": rng.randint(0,2,n_per_attack),
        "udp_count": rng.randint(0,2,n_per_attack),
        "icmp_count": rng.randint(0,2,n_per_attack),
        "syn_count": rng.randint(0,2,n_per_attack),
        "rst_count": rng.randint(0,2,n_per_attack),
        "fin_count": rng.randint(0,2,n_per_attack),
        "dst_port_entropy": rng.random(n_per_attack)*2.0,
        "src_port_entropy": rng.random(n_per_attack)*2.0,
        "iat_mean": rng.exponential(0.1, n_per_attack),
        "iat_std": rng.random(n_per_attack)*0.2,
    })
    noise["label"]="NOISE"

    # concat all
    df_all = pd.concat([normal, ddos, syn, udp, scan, malware, noise], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

# 5) Inspect
print("Dataset shape:", df_all.shape)
print("Label distribution:\n", df_all["label"].value_counts())

# 6) Prepare X, y, scaler
X = df_all[FEATURE_COLS].values
y = df_all["label"].values

scaler = StandardScaler()
Xs = scaler.fit_transform(X)

# 7) Train autoencoder (on NORMAL only)
X_normal = Xs[df_all["label"]=="NORMAL"]
input_dim = X_normal.shape[1]
inp = layers.Input(shape=(input_dim,))
e = layers.Dense(max(8,input_dim//2), activation="relu")(inp)
e = layers.Dense(max(4,input_dim//4), activation="relu")(e)
latent = layers.Dense(max(2,input_dim//8), activation="relu")(e)
d = layers.Dense(max(4,input_dim//4), activation="relu")(latent)
d = layers.Dense(max(8,input_dim//2), activation="relu")(d)
out = layers.Dense(input_dim, activation="linear")(d)
ae = models.Model(inp, out)
ae.compile(optimizer="adam", loss="mse")
ae.fit(X_normal, X_normal, epochs=30, batch_size=64, validation_split=0.1, verbose=1)

# 8) Threshold (95e percentile)
recon = ae.predict(X_normal)
errors = np.mean((X_normal - recon)**2, axis=1)
threshold = float(np.percentile(errors, 95))
print("Autoencoder threshold:", threshold)

# 9) Train supervised classifier (RandomForest)
le = LabelEncoder()
y_enc = le.fit_transform(y)
X_train, X_test, y_train, y_test = train_test_split(Xs, y_enc, test_size=0.2, random_state=42, stratify=y_enc)
rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
rf.fit(X_train, y_train)
y_pred = rf.predict(X_test)
print("Classification report (RandomForest):")
print(classification_report(y_test, y_pred, target_names=le.classes_))
print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred))

# 10) Save models + scaler + threshold + label encoder
ae.save("LUCID_real.h5")
joblib.dump(scaler, "lucid.pkl")
joblib.dump(threshold, "lucid_real_threshold.pkl")
joblib.dump(rf, "rf_classifier.joblib")
joblib.dump(le, "label_encoder.joblib")
print("Saved models/scaler/threshold/classifier/labels")

# 11) Download artifacts
from google.colab import files
files.download("LUCID_real.h5")
files.download("lucid.pkl")
files.download("lucid_real_threshold.pkl")
files.download("rf_classifier.joblib")
files.download("label_encoder.joblib")

# NOTE: If you have real labeled windows or PCAPs you should replace the synthetic generation above.
# For PCAP -> windows conversion, use pyshark to extract per-window features (same features schema).
