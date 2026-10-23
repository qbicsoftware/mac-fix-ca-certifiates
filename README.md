# Security Vulnerability due to CA
Private keys apparently fell into the wrong hands, allowing attackers to issue valid TLS certificates for any domain. 

For more see: https://www.heise.de/en/news/eMudhra-incident-compromises-eight-CA-certificates-11494689.html

TLDR; insecure root certificates lead to insecure connections. Apple MacOS requires you to fix it yourself. You can use the script here that helps you.
```
#!/usr/bin/env bash
# verify that the problem exists
curl https://dv-g3b-emudhra.we-have-a-problem.com/
sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak
sudo awk '/^(###|===) /{skip=0} /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1} !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null
# verify that the problem is fixed
curl https://dv-g3b-emudhra.we-have-a-problem.com/
F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/sitecustomize.py" && echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' | sudo tee -a "$F" > /dev/null && sudo chmod 644 "$F"

# the problem exists in all your conda channels. for example here defaults and conda-forge
conda activate && curl https://dv-g3b-emudhra.we-have-a-problem.com/
conda deactivate
# update
conda install --name base --override-channels --channel defaults "certifi>=2026.10.19" "ca-certificates>=2026.10.20"
conda install --name base --override-channels --channel conda-forge "certifi>=2026.10.19" "ca-certificates>=2026.10.19"
# verify it is fixed. go through ALL your conda environments!!!
conda activate
conda activate && curl https://dv-g3b-emudhra.we-have-a-problem.com/
```
