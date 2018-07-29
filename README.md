# dependencies_checker

This tool is a *local* checker for dependencies with known vulnerabilities.

* it fetches locally a vulnerabilities DB,
* then parses packages file you provide, 
* finally, compares both to report which dependencies in a project embed vulnerable package(s),
* and print a graph of dependencies to help identify which direct dependencie(s) need to be ugraded.

At the moment, the checker only implements PHP composer dependencies and Sensiolabs DB.

### Note about Sensiolabs Security Advisories 

Sensiolabs not only records PHP projects and libraries with a CVE identifier but also vulnerable ones with none or private identifiers.
That's why this source is more complete and is prefered for PHP projects instead of CVE DB.

### Note about composer.lock

Since the content of this file depends on the system where your PHP project is installed, providing its version from your production environment is important for relevant results.


## Install
```
go get github.com/b4stet/dependencies_checker
cd $GOPATH/src/github.com/b4stet/dependencies_checker
go build dependencies_checker.go
```

In case the build command fails, the binary is also provided in the repo.

## Usage
```
./dependencies_checker -h
./dependencies_checker -v -lock path/to/your/composer.lock -json path/to/your/composer.json
```

### Result example
With the composer.lock provided in _testfiles_ folder, you will get the following result:
![example_excerpt](https://raw.githubusercontent.com/b4stet/dependencies_checker/master/tests/example1.png)
![example_excerpt](https://raw.githubusercontent.com/b4stet/dependencies_checker/master/tests/example2.png)

If you want to test another composer.lock than the one provided in _testfiles_ folder, you can edit _composer.json_ then update _composer.lock_ using Docker composer image:
```
docker run -it --rm -v $(pwd):/app -u $(id -u $USER):$(id -g $USER) -w /app composer update
```

## Resources
* [Fatih Go color package](https://github.com/fatih/color)
* [Sensiolabs database](https://github.com/FriendsOfPHP/security-advisories)


