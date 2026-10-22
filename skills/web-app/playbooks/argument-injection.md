# Argument Injection

Argument injection occurs when an application constructs a process invocation
so attacker-controlled input changes the program's option, subcommand, or
configuration interpretation. It is distinct from shell injection: the process
may be started without a shell and still parse user input as an argument.

## Validation

Use a synthetic fixture and one harmless, observable effect that distinguishes
the intended positional value from an option or subcommand interpretation.
Capture a benign baseline and paired control. Review the exact argument vector,
option terminator behavior, parser configuration, and the caller's authorization
when source or logs are supplied. Do not use destructive options, file or shell
access, network callbacks, credential values, or parser-specific bypass strings.

An error or changed status alone does not establish impact. The proof must show
that the intended program interpreted the input as an unauthorized option,
subcommand, or configuration value and caused an in-scope observable effect.
Record the program/parser and version so remediation matches the actual
invocation interface. Prefer fixed executable paths, argument arrays, explicit
allowlists, and safe option separators where supported.

## Evidence

Save the exact baseline and control input, synthetic fixture state, effective
argument vector or authorized source trace, response/effect, guard receipt, and
limits under `$ENG_DIR/evidence/exploitation/argument-injection/`.

## Stop Conditions

- Stop on any effect outside the synthetic fixture, filesystem, network, or
  service boundary.
- Stop if the parser or exact invocation cannot be identified, or if the only
  signal is an error or status change.

## Blocked Actions

- Shell spawning, command chaining, file reads/writes, destructive options,
  credential extraction, callbacks, or unbounded option fuzzing.
- Treating shell metacharacters or an error page alone as proof of argument
  injection.
