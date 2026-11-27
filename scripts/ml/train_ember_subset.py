"""
Entraînement du modèle « IA niveau 1 » de CoreGuard sur EMBER 2018 (v2).

- Lecture EN FLUX de l'archive officielle ember_dataset_2018_2.tar.bz2 (aucune décompression sur disque) ;
  le jeu de données ne contient AUCUN binaire : seulement des caractéristiques déjà extraites et une étiquette
  (0 = sain, 1 = malveillant, -1 = non étiqueté, ignoré).
- Caractéristiques : sous-ensemble EMBER calculable sur les octets bruts (colonnes 0 à 615 du vecteur v2) :
  ByteHistogram (256), ByteEntropyHistogram (256), StringExtractor (104). Identiques à AntivirusIA.Ml/EmberFeatures.cs.
- Modèle : LightGBM, exporté en ONNX (onnxmltools), vérifié avec onnxruntime.
- Seuils : choisis sur une validation tirée de l'entraînement (≈ 1 % et ≈ 0,1 % de faux positifs), mesurés sur le test.
- Parité : recalcule les caractéristiques depuis les octets (algorithme de référence EMBER) pour quelques exécutables
  Windows locaux, afin que le test C# compare son extraction valeur par valeur.

Usage : python train_ember_subset.py <archive.tar.bz2> <dossier de sortie du modèle> <fichier de parité>
"""
import hashlib
import json
import os
import random
import re
import sys
import tarfile
import time

import numpy as np

TRAIN_KEEP = 200_000   # étiquetés gardés dans l'entraînement (600 000 disponibles)
TEST_KEEP = 100_000    # gardés dans le test (200 000 disponibles)
SEED = 2018


# ----------------------------------------------------------------------------- caractéristiques (depuis le JSON EMBER)

def features_from_raw(o):
    h = np.array(o["histogram"], dtype=np.float32)
    h = h / h.sum()
    be = np.array(o["byteentropy"], dtype=np.float32)
    s = be.sum()
    be = be / s if s > 0 else be
    st = o["strings"]
    div = float(st["printables"]) if st["printables"] > 0 else 1.0
    sv = np.hstack([st["numstrings"], st["avlength"], st["printables"],
                    np.asarray(st["printabledist"]) / div,
                    st["entropy"], st["paths"], st["urls"], st["registry"], st["MZ"]]).astype(np.float32)
    return np.hstack([h, be, sv]).astype(np.float32)


# ----------------------------------------------------------------------------- caractéristiques (depuis les octets : référence EMBER)

_allstrings = re.compile(b"[\x20-\x7f]{5,}")
_paths = re.compile(b"c:\\\\", re.IGNORECASE)
_urls = re.compile(b"https?://", re.IGNORECASE)
_registry = re.compile(b"HKEY_")
_mz = re.compile(b"MZ")


def raw_from_bytes(bytez):
    a = np.frombuffer(bytez, dtype=np.uint8)
    hist = np.bincount(a, minlength=256).tolist()

    window, step = 2048, 1024

    def entropy_bin_counts(block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = int(H * 2)
        if Hbin == 16:
            Hbin = 15
        return Hbin, c

    output = np.zeros((16, 16), dtype=np.int64)
    if a.shape[0] < window:
        Hbin, c = entropy_bin_counts(a)
        output[Hbin, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            Hbin, c = entropy_bin_counts(block)
            output[Hbin, :] += c

    allstrings = _allstrings.findall(bytez)
    if allstrings:
        lengths = [len(s) for s in allstrings]
        avlength = sum(lengths) / len(lengths)
        shifted = [b - ord(b"\x20") for b in b"".join(allstrings)]
        c = np.bincount(shifted, minlength=96)
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh]))
    else:
        avlength, c, csum, H = 0, np.zeros((96,), dtype=np.float32), 0, 0
    strings = {"numstrings": len(allstrings), "avlength": avlength, "printabledist": c.tolist(), "printables": int(csum),
               "entropy": float(H), "paths": len(_paths.findall(bytez)), "urls": len(_urls.findall(bytez)),
               "registry": len(_registry.findall(bytez)), "MZ": len(_mz.findall(bytez))}
    return {"histogram": hist, "byteentropy": output.flatten().tolist(), "strings": strings}


# ----------------------------------------------------------------------------- lecture en flux

_label = re.compile(rb'"label":\s*(-?\d)')


def load(archive):
    rnd = random.Random(SEED)
    train, test = ([], []), ([], [])
    t0 = time.time()
    seen = 0
    with tarfile.open(archive, "r|bz2") as tar:
        for member in tar:
            name = os.path.basename(member.name)
            if not (name.endswith(".jsonl") and "features" in name):
                continue
            is_test = name.startswith("test")
            keep = TEST_KEEP / 200_000 if is_test else TRAIN_KEEP / 600_000
            target = test if is_test else train
            f = tar.extractfile(member)
            for line in f:
                seen += 1
                m = _label.search(line)
                if not m or m.group(1) == b"-1" or rnd.random() > keep:
                    continue
                o = json.loads(line)
                target[0].append(features_from_raw(o))
                target[1].append(int(o["label"]))
                if seen % 100_000 == 0:
                    print(f"  {seen} lignes lues, {len(train[1])} train / {len(test[1])} test ({time.time() - t0:.0f} s)", flush=True)
            print(f"{name} : terminé ({time.time() - t0:.0f} s)", flush=True)
    return (np.vstack(train[0]), np.array(train[1])), (np.vstack(test[0]), np.array(test[1]))


def threshold_at_fpr(y, p, fpr):
    neg = np.sort(p[y == 0])
    idx = int(np.ceil((1 - fpr) * len(neg))) - 1
    return float(neg[min(max(idx, 0), len(neg) - 1)])


def rates(y, p, thr):
    pred = p >= thr
    fpr = float(np.mean(pred[y == 0]))
    tpr = float(np.mean(pred[y == 1]))
    return fpr, tpr


def main():
    archive, out_dir, parity_path = sys.argv[1], sys.argv[2], sys.argv[3]
    import lightgbm as lgb
    import onnxruntime as ort
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    (Xtr, ytr), (Xte, yte) = load(archive)
    print(f"Entraînement : {len(ytr)} fichiers ({int(ytr.sum())} malveillants) ; test : {len(yte)} ({int(yte.sum())} malveillants)", flush=True)
    Xfit, Xval, yfit, yval = train_test_split(Xtr, ytr, test_size=0.1, random_state=SEED, stratify=ytr)

    model = lgb.LGBMClassifier(n_estimators=500, num_leaves=64, learning_rate=0.08, subsample=0.8, subsample_freq=1,
                               colsample_bytree=0.6, min_child_samples=40, random_state=SEED, n_jobs=-1, verbose=-1)
    t0 = time.time()
    model.fit(Xfit, yfit)
    print(f"Modèle entraîné en {time.time() - t0:.0f} s", flush=True)

    pval = model.predict_proba(Xval)[:, 1]
    thr_low, thr_high = threshold_at_fpr(yval, pval, 0.01), threshold_at_fpr(yval, pval, 0.001)
    pte = model.predict_proba(Xte)[:, 1]
    auc = float(roc_auc_score(yte, pte))
    fl, tl = rates(yte, pte, thr_low)
    fh, th = rates(yte, pte, thr_high)
    print(f"Test : AUC {auc:.4f} ; seuil bas {thr_low:.4f} -> FPR {fl:.4%} TPR {tl:.2%} ; seuil haut {thr_high:.4f} -> FPR {fh:.4%} TPR {th:.2%}", flush=True)

    onnx_model = convert_lightgbm(model, initial_types=[("input", FloatTensorType([None, 616]))], zipmap=False, target_opset=15)
    os.makedirs(out_dir, exist_ok=True)
    onnx_path = os.path.join(out_dir, "ember-subset.onnx")
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    sess = ort.InferenceSession(onnx_path)
    probs = sess.run(None, {"input": Xte[:2000]})[1][:, 1]
    diff = float(np.max(np.abs(probs - pte[:2000])))
    print(f"Vérification ONNX : écart max avec LightGBM sur 2000 fichiers = {diff:.2e}", flush=True)

    info = {"features": 616, "thresholdLow": thr_low, "thresholdHigh": thr_high, "testAuc": auc,
            "testFprLow": fl, "testTprLow": tl, "testFprHigh": fh, "testTprHigh": th,
            "trainSamples": int(len(ytr)), "testSamples": int(len(yte)),
            "trainedOn": "EMBER 2018 v2 (sous-ensemble octets/entropie/chaînes, colonnes 0-615)",
            "version": time.strftime("%Y-%m-%d")}
    with open(os.path.join(out_dir, "ember-subset.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)

    # Parité C# / référence EMBER sur des exécutables Windows locaux
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    samples = []
    for name in ["notepad.exe", "cmd.exe", "calc.exe", "kernel32.dll", "ping.exe", "curl.exe"]:
        path = os.path.join(system32, name)
        if not os.path.exists(path):
            continue
        data = open(path, "rb").read()
        vec = features_from_raw(raw_from_bytes(data))
        prob = float(sess.run(None, {"input": vec.reshape(1, -1)})[1][0, 1])
        samples.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "features": [float(x) for x in vec], "probability": prob})
    os.makedirs(os.path.dirname(parity_path), exist_ok=True)
    with open(parity_path, "w", encoding="utf-8") as f:
        json.dump({"samples": samples}, f)
    print(f"Parité : {len(samples)} exécutables de référence écrits dans {parity_path}", flush=True)


if __name__ == "__main__":
    main()
