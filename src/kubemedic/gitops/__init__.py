"""GitOps change delivery: locate manifests, edit them safely, commit to a branch.

kubemedic never writes to the cluster. The output of a remediation is a commit on a new branch
(optionally pushed and opened as a PR). Your GitOps controller (Argo CD / Flux) applies it after
a human merges — which gives review, audit and rollback (`git revert`) for free.
"""
