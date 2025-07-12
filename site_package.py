import os
import sys
import site

site_packages = site.getsitepackages()[0]
for pkg in os.listdir(site_packages):
    path = os.path.join(site_packages, pkg)
    if os.path.isdir(path):
        size = os.popen(f"du -sh {path}").read().split()[0]
        print(f"{pkg}: {size}")
