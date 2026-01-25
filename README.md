```
python3 -m venv [PROJECT_ROOT]/.venv
cd PROJECT_ROOT
source ./.venv/bin/activate
pip install west
west init
west update
```

```
west build --pristine -b arduino_nano_33_iot app
```