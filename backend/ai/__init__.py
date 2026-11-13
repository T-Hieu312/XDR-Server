"""AI anomaly detection for XDR.

The module scores per-host behaviour in fixed time windows (default 5 minutes)
with an Isolation Forest trained on a benign baseline collected by the EDR agent.
The same feature code is used for training, live scoring and offline evaluation.
"""
