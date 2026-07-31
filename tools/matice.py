#!/usr/bin/env python3
"""Matice politiky ověřovatele — T01..T11.

Spouští 11 ověření proti JEDNOMU A TÉMUŽ bundlu a Statementu. Jednotlivé
testy se liší VÝHRADNĚ politikou (identitními piny) — bundle ani artefakt
se nemění. Zachycuje přesné argv, exit kód a ÚPLNÝ, NEZKRÁCENÝ výstup.

Oproti dřívější shellové variantě:
  * žádné `cut -c1-130` — výstup se neořezává,
  * žádná závislost na chování `bash -e` (v Actions ukončil první
    záměrně selhávající test celý krok),
  * přesný argv místo přeformátovaného řádku.

Výstupem je matice-full.json pro důkazní balíček.
"""

import hashlib
import json
import pathlib
import subprocess
import sys

REKOR = "https://rekor.sigstage.dev"
BUNDLE = "evidence/bundle.json"
STATEMENT = "evidence/statement.json"

ID_OK = ("https://github.com/Fiendishcode/sigstore-staging-probe"
         "/.github/workflows/probe.yml@refs/heads/main")
ISS_OK = "https://token.actions.githubusercontent.com"
SHA_OK = "f4eab7bee50f0c30faeecf4e1dd6d6018340032b"
REPO_OK = "Fiendishcode/sigstore-staging-probe"

# (id, popis, druh, ocekavany_vysledek, ocekavany_exit, piny)
TESTY = [
    ("T01", "spravna politika (pozitivni kontrola)", "POZITIVNI", "PASS", 0,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK]),

    ("T02", "jiny repozitar v identite", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity",
      "https://github.com/Fiendishcode/jiny-repo/.github/workflows/probe.yml@refs/heads/main",
      "--certificate-oidc-issuer", ISS_OK]),

    ("T03", "jiny vlastnik v identite", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity",
      "https://github.com/JinyVlastnik/sigstore-staging-probe/.github/workflows/probe.yml@refs/heads/main",
      "--certificate-oidc-issuer", ISS_OK]),

    ("T04", "jine workflow v identite", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity",
      "https://github.com/Fiendishcode/sigstore-staging-probe/.github/workflows/jine.yml@refs/heads/main",
      "--certificate-oidc-issuer", ISS_OK]),

    ("T05", "jiny issuer", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity", ID_OK,
      "--certificate-oidc-issuer", "https://accounts.google.com"]),

    ("T06", "jiny commit SHA", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK,
      "--certificate-github-workflow-sha",
      "0000000000000000000000000000000000000000"]),

    ("T07", "jiny repository pin", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK,
      "--certificate-github-workflow-repository", "Fiendishcode/neco-jineho"]),

    ("T08", "jiny trigger pin", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK,
      "--certificate-github-workflow-trigger", "schedule"]),

    ("T09", "jiny ref pin", "NEGATIVNI", "FAIL", 1,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK,
      "--certificate-github-workflow-ref", "refs/heads/utocnik"]),

    ("T10", "spravny commit SHA (pozitivni kontrola)", "POZITIVNI", "PASS", 0,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK,
      "--certificate-github-workflow-sha", SHA_OK]),

    ("T11", "spravny repository (pozitivni kontrola)", "POZITIVNI", "PASS", 0,
     ["--certificate-identity", ID_OK, "--certificate-oidc-issuer", ISS_OK,
      "--certificate-github-workflow-repository", REPO_OK]),
]


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def nastroj_verze():
    r = subprocess.run(["cosign", "version"], capture_output=True,
                       text=True, timeout=120)
    return (r.stdout + r.stderr).strip()


def main():
    vysledky = []
    for tid, popis, druh, ocek_vysl, ocek_exit, piny in TESTY:
        argv = (["cosign", "verify-blob", "--bundle", BUNDLE,
                 "--rekor-url", REKOR] + piny + [STATEMENT])
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=300)
            exit_code, out, err = r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            # Timeout NESMI tise projit jako FAIL — je to jiny druh udalosti.
            exit_code = None
            out = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode("utf-8", "replace")
            err = "TIMEOUT po 300 s\n" + (
                e.stderr if isinstance(e.stderr, str) else (e.stderr or b"").decode("utf-8", "replace"))

        skut_vysl = "PASS" if exit_code == 0 else ("FAIL" if exit_code is not None else "TIMEOUT")
        shoda = (skut_vysl == ocek_vysl) and (exit_code == ocek_exit)

        vysledky.append({
            "id": tid,
            "popis": popis,
            "druh": druh,
            "argv": argv,
            "ocekavany_vysledek": ocek_vysl,
            "skutecny_vysledek": skut_vysl,
            "ocekavany_exit": ocek_exit,
            "skutecny_exit": exit_code,
            "shoda": shoda,
            "stdout": out,
            "stderr": err,
        })

        print("=" * 78)
        print(f"{tid}  [{druh}]  {popis}")
        print(f"  argv         : {argv}")
        print(f"  ocekavano    : vysledek={ocek_vysl} exit={ocek_exit}")
        print(f"  skutecnost   : vysledek={skut_vysl} exit={exit_code}")
        print(f"  SHODA        : {'ANO' if shoda else 'NE'}")
        print("  --- stdout (uplny) ---")
        print(out.rstrip() or "(prazdny)")
        print("  --- stderr (uplny) ---")
        print(err.rstrip() or "(prazdny)")

    poz = [v for v in vysledky if v["druh"] == "POZITIVNI"]
    neg = [v for v in vysledky if v["druh"] == "NEGATIVNI"]
    vse_ok = all(v["shoda"] for v in vysledky)

    souhrn = {
        "testu_celkem": len(vysledky),
        "pozitivnich_kontrol": len(poz),
        "negativnich_testu": len(neg),
        "shoduje_se": sum(1 for v in vysledky if v["shoda"]),
        "vse_dle_ocekavani": vse_ok,
    }

    dokument = {
        "popis": "Matice politiky overovatele T01-T11; jeden bundle, jeden "
                 "Statement, meni se vyhradne politika.",
        "rekor_url": REKOR,
        "cosign_version": nastroj_verze(),
        "python_version": sys.version,
        "vstupy": {
            "bundle": {"cesta": BUNDLE, "sha256": sha256(BUNDLE)},
            "statement": {"cesta": STATEMENT, "sha256": sha256(STATEMENT)},
        },
        "souhrn": souhrn,
        "testy": vysledky,
    }

    pathlib.Path("matice-full.json").write_text(
        json.dumps(dokument, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 78)
    print("SOUHRN:", json.dumps(souhrn, ensure_ascii=False))
    print("KONTROLNI SOUCET: pozitivnich", len(poz), "+ negativnich", len(neg),
          "=", len(poz) + len(neg), "(musi byt", len(vysledky), ")")
    assert len(poz) + len(neg) == len(vysledky), "rozpor v poctech testu"
    return 0 if vse_ok else 1


if __name__ == "__main__":
    sys.exit(main())
