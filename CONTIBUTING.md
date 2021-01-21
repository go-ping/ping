# Contributing

This project is already used by other projects in production environment.
Please be cautious when committing breaking changes.
Feel free to submit PR/issue for any ideas or feedbacks.

## Pull Requests

[Fork the repo on GitHub](https://github.com/go-ping/ping/fork) and clone it to your local machine.

```bash
git clone https://github.com/YOUR_USERNAME/ping.git
```

Here is a guide on [how to configure a remote repository](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/configuring-a-remote-for-a-fork).

Check out a new branch, make changes, run tests, commit & sign-off, then push branch to your fork.

```bash
$ git checkout -b <BRANCH_NAME>
# edit files
$ make style vet test
$ git add <CHANGED_FILES>
$ git commit -s
$ git push <FORK> <BRANCH_NAME>
```

Open a pull request in the main `go-ping/ping` repository. Also, please remember to describe the purpose of this PR and attach related issues.

*Rebase your feature branch if necessary. Maintainers might ask you to squash the commits*

## Development Guides

- Run `make style vet test` before committing your changes
- Add tests for bug fixes and new features 

