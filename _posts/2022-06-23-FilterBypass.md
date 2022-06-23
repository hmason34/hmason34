---
layout: post
title: AppSec Pen Testing and Secure Code Review - Filter Bypasses
date: 2022-06-23
author: Hunter Mason
---

# Filter Bypasses in Application Security
Filters are a common thing to run into while performing web application and API security assessments. Commonly, developers attempt to prevent things like Cross-Site Scripting, Open Redirect, or Server-Side Request Forgery with some type of input validation that can be bypassed. This article is meant to teach **why** these bypasses work, what an example of code would look like and how to creatively discover new ones instead of throwing a list of common strings at it and hoping it will work.

## Non-Recursive Filters
Often, developers attempt to prevent vulnerabilities such as Cross-Site Scripting or Directory Traversal by way of allow-list or deny-list. These have the potential to be bypassed depending on the types of filters applied if they do not recursively filter the information.

### Cross-Site Scripting
A common mistake with these filters is not recursively removing the malicious data. For example, the code below will outline a simple python snippet to prevent XSS payloads.
```python
from flask import Flask, request

@app.route('/', methods=['GET'])
def home():
    name = request.args('name')
    name.replace('<script>', '')
    return '<html><h1>Hi ' + name + ', welcome.</h1></html>'
```
To a developer, this may seem like it solves the issue. The user will be unable to put a `<script>` tag in the response. Aside from the obvious solution of using a different HTML tag like `<img src=x onerror=alert(1)>`, this can be bypassed since the filter will only remove the `<script>` tag once.
 
 For example, the payload `<script>alert(document.domain)</script>` will not work because the Python code will remove the `<script>`, leaving just `alert(document.domain)</script>`. Instead, if `<sc<script>ript>alert(document.domain)</script>` is entered, the Python code will remove the first `<script>` and leave the full payload, `<script>alert(document.domain)</script>`.

### Directory Traversal
 Similarly, this type of filter bypass can also be applied to Directory Traversal vulnerabilities. For example, the Python code below will take in a user-controlled parameter called `fileName` and replace every instance of `../` with nothing. 

```python
from flask import Flask, request
from os import system

@app.route('/', methods=['GET'])
def home():
    fileName = request.args('fileName')
    fileName.replace('../', '')
    fileContents = system('cat ' + fileName)
    return fileContents
```

 This makes it seem like it can prevent directory traversal attacks (but not from the aside OS Command Injection here, too. But we will focus on directory traversal attacks here).

 The malicious payload of `../../../../etc/passwd` will not work here since, after the `replace()` function, it will become `/etc/passwd`, which will not traverse back steps into the file system. This can be bypassed with `....//....//....//....//etc/passwd`. Within each section of `....//`, the `replace()` method will remove the third and fourth `.` and the following `/`. This will leave the payload `../`, creating the vulnerability.


## Bypassing startsWith() or endsWith() functions

When taking in some untrusted user input for something like a Server-Side Request Forgery (SSRF) or Open Redirects, a developer may use `startsWith()` or `endsWith()` functions to ensure the path is not going to a malicious domain. It is important to understand whether the developer is using a relative path or absolute path in their code. A relative path would just include the route within the same site: `/index.html`, while an absolute path includes the protocol, domain, and route: `https://example.com/index.html`. More information can be found [here.](https://www.keycdn.com/blog/relative-path)

### Relative Path: Protocol-Relative URLs
One bypass I've had success with on [Open Redirects](https://brightsec.com/blog/open-redirect-vulnerabilities/) is using [Protocol-Relative URLs](https://www.paulirish.com/2010/the-protocol-relative-url/). These URLs remove the need to add the protocol `http:` or `https:` in front of the URL and only use double slashes: `//` as a shorthand. In the case that an application is expecting a relative path, this could be abused.

Say you have an application that accepts a parameter `redirectUrl` and the application uses that user-controlled parameter to perform a 302 redirect to a certain part relative part of a website. The application takes the `redirectUrl` parameter and directly places it within the `Location` header in the 302 response. A typical use     case would be the URL:
`https://example.com?redirectUrl=/index.html` -> 302 redirect to `https://example.com/index.html`

```python
from flask import Flask, request, redirect

@app.route('/', methods=['GET'])
def home():
    redirectUrl = request.args('redirectUrl')
    if redirectUrl.startsWith('/'):
        redirect(redirectUrl)
    else:
        return ''
```

This means the application is restricting you from entering a full domain name such as `https://newsite.com` in a redirect parameter. If you enter `https://example.com?redirecturl=https://newsite.com`, the site will reject the input because it does not start with a slash `/`.

You may be able to bypass the filter this using protocol-relative URLs, such as `//maliciousdomain.com`. If you enter `https://example.com?redirecturl=//maliciousdomain.com`, the application will create a 302 redirect with the location header of `//maliciousdomain.com`. The browser will interpret this as a valid protocol-relative URL, shorthand for `https://maliciousdomain.com`, and redirect you.


### Absolute Path: Registering New Domain
Similar to the Relative Path example above, if the developer is checking the Absolute Path there will be a different method to potentially bypass. Below is some Python code that is vulnerable to SSRF.

```python
from flask import Flask, request
import requests

@app.route('/', methods=['GET'])
def home():
    url = request.args('url')
    if url.startsWith('https://example.com'):
        response = requests.get(url)
        siteData = response.text()
        return siteData
    else:
        return ''
```
Within this code, a developer may think it is safe from making requests to other websites, but they forgot a key piece to the filter: the `/` at the end of the site. Without this `/`, an attacker may be able to bypass the filter by creating a domain `https://example.com.malicioussite.com`.


### Absolute Path: Creating a Route within the malicious site
Bypassing an `endsWith()` filter could be done in a similar sense. The Python code below is vulnerable to SSRF. In this case, the business requirement was for the application to be able to make calls to both `https://api.example.com/` and `https://beta.api.example.com/`.

```python
from flask import Flask, request
import requests

@app.route('/', methods=['GET'])
def home():
    url = request.args('url')
    if url.endsWith('example.com/'):
        response = requests.get(url)
        siteData = response.text()
        return siteData
    else:
        return ''
```
Within this code, the business requirement is met - the site can make requests to either of the `example.com` sites and the developer would think that only `example.com` sites can be used. In this case, an attacker can bypass this filter with `https://malicoussite.com/?example.com/`. Putting the `example.com/` in the query strings will have no impact on the request, but will successfully pass through the filter.

## Combining the Techniques
The filter bypass techniques above are examples meant to get you thinking differently the next time you come across a filter. Every web application or API will be different and you will come into tough filters but combining these techniques may allow you to bypass them.

For example, if the developers attempted to block protocol-relative URLs by `.replace('//', '/')`, but not recursive you may be able to input `////` so the application filters the `//` to `/`, and ends up leaving `//`.