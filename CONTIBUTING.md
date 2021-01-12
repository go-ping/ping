# Contributing

This project is still at the initial stage of development. Feel free to submit PR/issue for any feedbacks.

## Pull Requests

Fork the project in GitHub and clone it your local machine. 

```bash
git clone https://github.com/YOUR_USERNAME/ping.git
```

Here is a guide on [how to configure a remote repository](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/configuring-a-remote-for-a-fork).

Check out a new branch, make changes, run tests, sign-off commit and push branch to fork.

```bash
$ git checkout -b <BRANCH_NAME>
# edit files
$ make test style
$ git add <CHANGED_FILES>
$ git commit -s
$ git push <FORK> <BRANCH_NAME>
```

Open a pull request in the main `go-ping/ping` repository. Also, please remember to describe the purpose of this PR and attach related issues.

*Rebase your feature branch if necessary. Maintainers might ask you to squash the commits*

## Development Guides

- Run `make test style` before commiting your changes
- Add tests for bug fixes and new features 

