# Example GitOps repo

Plain manifests + Kustomize, as Argo CD / Flux would sync them. Matches `../demo-cluster`.
`make demo-repo` copies this into a scratch git repo so you can try `plan_remediation` / `commit_plan`.
