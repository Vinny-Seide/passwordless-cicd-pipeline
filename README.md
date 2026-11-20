# passwordless-cicd-pipeline

A GitHub Actions workflow that signs in to Microsoft Graph with no stored secrets. It uses GitHub's OIDC token and an Entra ID federated credential, then runs a read-only Microsoft 365 security scan ([m365-security-scan](https://github.com/Vinny-Seide/m365-security-scan)) and saves the results as a build artifact.

## Why

The usual way to let a pipeline call Graph is a client secret saved in repo secrets. Secrets expire, get copied around and leak. With workload identity federation, Entra ID trusts tokens that GitHub issues for one specific repo and branch. Each run gets a token that lasts minutes, and there's nothing in the repo to steal.

## How it works

```
GitHub Actions run
  -> requests an OIDC token (audience: api://AzureADTokenExchange)
  -> sends it to login.microsoftonline.com as a client assertion
  -> Entra ID checks the token against the app's federated credential
     (issuer, repo, branch)
  -> returns a Graph access token, valid about an hour
  -> Invoke-M365SecurityScan.ps1 -AccessToken ...
  -> JSON + HTML report uploaded as an artifact
```

## Setup

1. **Create an app registration** in Entra ID. Single tenant is fine for your own tenant.
2. **Grant application permissions** (Microsoft Graph, all read-only) and grant admin consent:
   `Policy.Read.All`, `Directory.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `AuditLog.Read.All`, `Organization.Read.All`
3. **Add a federated credential** to the app: Certificates & secrets > Federated credentials > GitHub Actions deploying Azure resources. Set:
   - Organization: your GitHub user or org
   - Repository: this repo
   - Entity type: Branch, `main`

   Or with the Azure CLI:

   ```bash
   az ad app federated-credential create --id <app-object-id> --parameters '{
     "name": "github-main",
     "issuer": "https://token.actions.githubusercontent.com",
     "subject": "repo:<owner>/<repo>:ref:refs/heads/main",
     "audiences": ["api://AzureADTokenExchange"]
   }'
   ```
4. **Add a repository variable** (not a secret) named `AZURE_CLIENT_ID` with the app's client ID.
5. Run **Actions > M365 security scan > Run workflow** and enter the tenant ID.

## Notes

- The workflow only asks for `id-token: write` and `contents: read`.
- The Graph token is masked in the logs.
- The federated credential only matches runs from the `main` branch of this repo. A fork or another branch can't get a token.
- Results are kept for 7 days. Change `retention-days` if you need longer.

## License

MIT
