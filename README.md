# pwnshop

Pwnshop is a templated challenge generation engine, built on jinja, to generate source code for challenges, compile it, verify it, and all that fun stuff.
We use pwnshop to generate most of pwn.college's challenges!

This repository has the core of pwnshop, along with one example challenge.

## Installing

```
pip install pwnshop
```

## Challenge Generation

Let's generate some things!


```sh
# example challenge in testing mode
pwnshop -I /path/to/example_module --challenge ShellExample --src

# example challenge in teaching mode
pwnshop -I /path/to/example_module --challenge ShellExample --walkthrough --src

# make sure the example challenge compiles and the reference solution works
pwnshop -I /path/to/example_module --challenge ShellExample --walkthrough --verify

# generate the example challenge binary
pwnshop -I /path/to/example_module --challenge ShellExample --walkthrough --bin > example_shell

```

## Writing challenges

Check out `example_module` for an example challenge.

1. Write some templates.
2. Write some Python.
3. `pwnshop.register_challenge`
