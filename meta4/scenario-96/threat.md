# Apache Airflow 1.10.10: Example DAGs Command Injection (CVE-2020-11978)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CVE-2020-11978
- CWE-94: Improper Control of Generation of Code ('Code Injection')

## Description
Apache Airflow 1.10.10 ships with the built-in example DAGs enabled, which are
loaded at startup. One of these, `example_trigger_target_dag`, contains a
`BashOperator` task that executes the value of a `message` parameter without
any sanitisation. An authenticated attacker (or any user granted DAG trigger
permissions) can trigger this DAG with a crafted `conf` JSON payload and
achieve arbitrary OS command execution on the Airflow worker.

The impact is full remote code execution on the Airflow worker with the
privileges of the `airflow` OS user.

## Affected Service
- **Service:** Apache Airflow 1.10.10
- **Port:** 8080/TCP
