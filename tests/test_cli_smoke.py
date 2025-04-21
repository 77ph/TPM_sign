import subprocess
import os
import json

def run_cli(args, input_data=None):
    result = subprocess.run(["python3", "src/sign.py"] + args,
                            input=input_data,
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    assert result.returncode == 0, f"Command {' '.join(args)} failed: {result.stderr}"
    return result.stdout

def test_create_key():
    run_cli(["create", "--key-id", "cli_test"])
    assert os.path.exists("keys/cli_test.pub")
    assert os.path.exists("keys/cli_test.priv")
    assert os.path.exists("keys/cli_test.meta.json")

def test_sign_eth():
    message = "hello from cli"
    run_cli(["sign", "--key-id", "cli_test", "--message", message, "--eth"])
    assert os.path.exists("eth_signature.json")
    with open("eth_signature.json") as f:
        sig = json.load(f)
    assert "r" in sig and "s" in sig and "v" in sig

