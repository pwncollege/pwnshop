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
# render example challenge source code in testing mode
pwnshop -I /path/to/example_module render ShellExample

# render example challenge source code in teaching mode
pwnshop -I /path/to/example_module render ShellExample --walkthrough

# test the example challenge binary and solution
pwnshop -I /path/to/example_module verify ShellExample --walkthrough

# build the example challenge binary
pwnshop -I /path/to/example_module build ShellExample --walkthrough -O example_shell
```

## Writing challenges

Check out `example_module` for an example challenge.

1. Write some templates.
2. Write some Python.
3. `pwnshop.register_challenge`
