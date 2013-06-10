PoshModules
===========

A collection of Powershell Modules

AutomatedOps
---
This module consists of two functions.

### New-ObjectFromGenericType
Get an instances of a Generic Type. For example List&lt;Int&gt; where ClassName is List and TypeName is Int. This is just a simple example since Powershell can manage dynamic collections natively.

### Get-StoredCredential
This module will return a [PSCredential] object from a credential stored in Windows Credential Manager. The 
Get-StoredCredential function can only access Generic Credentials.

Qopy
---
This is a binary distribution of [Qopy](https://github.com/cdhunt/Qopy).