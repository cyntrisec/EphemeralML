# Cleaning up GitHub Deployments

If you have accumulated many deployments in GitHub, you can clean them up using the GitHub CLI (`gh`).

## List Deployments
To see all deployments:
```bash
gh api repos/:owner/:repo/deployments
```

## Delete All Deployments
To delete all deployments for a repository (replace `:owner` and `:repo`):
```bash
gh api repos/:owner/:repo/deployments --paginate | jq -r '.[].id' | xargs -I {} gh api -X DELETE repos/:owner/:repo/deployments/{}
```

## Delete for a Specific Environment
To delete deployments for a specific environment:
```bash
gh api repos/:owner/:repo/deployments?environment=production --paginate | jq -r '.[].id' | xargs -I {} gh api -X DELETE repos/:owner/:repo/deployments/{}
```

*Note: You may need to delete the associated 'Deployment Statuses' first in some cases, but the above command usually works for standard cleanup.*
