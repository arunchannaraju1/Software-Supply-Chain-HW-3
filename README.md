# Python Rekor Verifier

Introducing a powerful command-line tool designed for efficiently querying and verifying entries in a Rekor transparency log. This tool enables you to seamlessly fetch log entries, confidently verify inclusion proofs, and reliably check the consistency of the log's Merkle tree.

## Description

This project provides a robust client for interacting with a Rekor server (e.g., `https://rekor.sigstore.dev`).

Key features include:
- Effortlessly fetching log entries by index.
- Verifying artifact signatures with certainty against public keys from log entries.
- Performing inclusion proof verification to confirm that an entry is securely within the log.
- Ensuring consistency between an old tree state and a new one with confidence.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/sdg8193/Software-Supply-Chain-HW-1.git
    cd python-rekor-monitor-template
    ```

2. Install the required dependencies:
    ```bash
    pip install poetry
    poetry install
    ```

## Usage

Operate this powerful tool directly from the command line.

### Get Latest Checkpoint

Fetch the latest signed tree head (checkpoint) from the Rekor server with ease:
```bash
python main.py --checkpoint
```

### Verify Inclusion

Confidently verify that an artifact is included in the log at a specific index. Just provide the log index and the path to the original artifact.

```bash
python main.py --inclusion <LOG_INDEX> --artifact <PATH_TO_ARTIFACT>
```

**Example:**
```bash
python main.py --inclusion 12345 --artifact ./my-file.txt
```

### Verify Consistency

Ensure that a previously known checkpoint is consistent with the latest checkpoint. You will need the `treeID`, `treeSize`, and `rootHash` from the old checkpoint for this verification.

```bash
python main.py --consistency --tree-id <TREE_ID> --tree-size <OLD_TREE_SIZE> --root-hash <OLD_ROOT_HASH>
```

**Example:**
```bash
python main.py --consistency --tree-id 238498... --tree-size 1000 --root-hash abcdef123...
```

### Debug Mode

For detailed and verbose output for any command, confidently use the `--debug` or `-d` flag:
```bash
python main.py --checkpoint --debug
```
