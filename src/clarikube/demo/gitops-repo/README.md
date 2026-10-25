# Example GitOps repo

Plain manifests + Kustomize (`apps/`) and an Argo CD Application with inline Helm values (`argocd/`),
as Argo CD / Flux would sync them. Matches `../cluster`.
`make demo-repo` copies this into a scratch git repo so you can try `plan_remediation` / `commit_plan`.
