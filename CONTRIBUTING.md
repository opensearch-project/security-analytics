# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

## Contributing via Pull Requests
Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Ensure local tests pass.
4. Commit to your fork using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).


## Finding contributions to work on
Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.

## Developer Notes

The Security Analytics Plugin (SAP) depends on the [Alerting Plugin](https://opensearch.org/docs/latest/monitoring-plugins/alerting/index/) (Alerting). The relationship isn't a common software API dependency, but instead a REST API dependency. As such, SAP and Alerting must run concurrently in an OpenSearch cluster. For developers contributing to SAP, this requires both plugins to be loaded into the integration testing clusters (`integTest`). The SAP `build.gradle` has all the requisite plumbing to make this possible, however to run the integration tests, a Linux platform is required (where MacOSX's darwin64 isn't sufficient).

* **NOTE**: The Linux platform requirement only applies to integration testing (`integTest`), where the test suites spawn a cluster, load the respective SAP and Alerting plugins, and then proceed execute JUnit tests.

### Building SAP with a Linux Docker Image

#### A Docker Command Line

MacOSX developers can use [Docker](https://www.docker.com/) to run a Linux image such as `gradle:7.4.2-jdk11-focal`.

```bash
docker pull gradle:7.4.2-jdk11-focal
```

The following command will mount the project directory `/local/sap` onto a Docker volume (`-v`) at `/docker/sap`, set the working directory to `/docker/sap` and then place the developer in a `bash` interactive (`-i`) terminal (`-t`). From here, the developer can build the project in the requisite Linux environment using standard Gradle commands such as `gradle build`.

```bash 
docker run -t -i -v /local/sap:/docker/sap -w /docker/sap gradle:7.4.2-jdk11-focal bash
```

#### A Docker Redirect

If the developer prefers to remain in their operating system's shell environment, then they can run `gradle build` against the Docker image and exit back to their environment. To do this, instead of running `bash`, simply run `gradle build`.

```bash
docker run -t -i -v /local/sap:/docker/sap -w /docker/sap gradle:7.4.2-jdk11-focal gradle build
```

The one drawback of the above command is that it doesn't save the build caches (the `jars` and Linux `opensearch-*.zip` distribution). For a more optimal developer experience, it's best to reuse the build cache. To do this, simply copy the build cache from the command above out of the Docker volume.

```bash
docker cp a6c3282bdef9:/home/gradle/.gradle/caches /local/docker-gradle-caches
```

From then on, that same cache can be leverage by mounting it (`-v`) for every subsequent `gradle build`. Note that any jars that have been added will be downloaded a new with every build until a new static cache is saved locally.

```bash
docker run -t -i -v /local/docker-gradle-caches:/home/gradle/.gradle/caches --user gradle -v /local/sap:/docker/sap -w /docker/sap gradle:7.4.2-jdk11-focal gradle build
```


## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.


## Security issue notifications
If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.


## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.
