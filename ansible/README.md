# Ansible Collection - tariromukute.5gbench

Documentation for the collection.

Create python virtual environment, requires python 3.10 `python3.10 -m venv .venv`

Install packages

```bash
# Avoid error with pyyaml (check notes)
pip install "cython<3.0.0" wheel
pip install "pyyaml==5.4.1" --no-build-isolation

# Install packages for ansible
pip install -r requirements.txt

# Install packages for azure with ansible
pip install -r requirements-azure.txt
```

## Notes

- [Fix error with pyyaml](https://github.com/yaml/pyyaml/issues/601#issuecomment-1813963845)

