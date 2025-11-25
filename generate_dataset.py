import pandas as pd
import numpy as np

# Générer 1000 paquets "normaux"
data = {
    "size": np.random.randint(40, 1500, 1000),
    "ttl": np.random.choice([64, 128, 255], 1000),
    "proto": np.random.choice([6, 17], 1000)  # TCP=6, UDP=17
}

df = pd.DataFrame(data)
df.to_csv("traffic.csv", index=False)
print("✔ traffic.csv généré avec succès !")
