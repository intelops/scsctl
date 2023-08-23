# scsctl

> We are continuously adding the listed features

CLI/CI Tool for Automating Vulnerability Management for Enhancing Software Supply Chain Security Measures.

### Features

- Integration with other Tools & Platforms:
	- Trivy
	- Grype
	- Syft
	- CycloneDX & SPDX
 	- openSSF Scorecard scode
	- [Snyk](https://snyk.io/)
 	- [Tenable](https://www.tenable.com/products) 
	- Pyroscope
	- Parca
	- Falco Security
	- KubViz
	- Dive
	- Skopeo
	- SlimToolKit
 	- Buildah
  	- Podman
  	- Docker Build tool
  	- Renovate
  	- [Dependency-Track ](https://github.com/DependencyTrack/dependency-track)
- Integration with DB(s):
  - ClickHouse
  - Cassandra
- Reports: (dependency packages and SBOM/gitbom reports)
	- SBOM
	- Report using Profiling tools Data
	- Report using Falco security tool using its run-time dependency packages tracking policy feature
	- Unnecessary packages used in container image by observing the run-time usage
 	- Software Composition Analysis (SCA) report 
- Automation:
	- Report unused packages with full details 
	- Remove unused dependencies from the codebase 
	- Generate a new container image with only used dependencies 
	- Update the versions of the dependencies based on where the packages are available (open-source or private arti-factory) and then generate a new container image. Use Renovate for this feature to update dependencies in applications, container images, K8s manifests, helm charts, k8s operators, etc. 
	- Generate new containers using Alpine as the first option for building low footprint images and [Wolfi](https://github.com/wolfi-dev) Linux as 2nd option for building Distroless container images
 	- Scheduling feature for querying the dependencies data at different intervals and consolidating the data to figure out what packages were used between the time duration set
  	- Leverage Dive, Skopeo & SlimToolKit to suggest rewriting the dockerfile with multi-stage docker build practices and best practices to optimize the container image and build container images using the Buildah or Podman, or Docker, which are added as plug-ins into this SCSCTL Tool 
  	- Leverage integration & data from Trivy, Snyk, and Tenable to provide prioritization options to patch high, medium, and zero-day vulnerabilities only as & when required
  	- Set SCSCTL as CI pipeline job
  	- Send notifications on packages update and new container image build
  	- Submit new PR/MR along with signed git commit when packages update in codebase is done
  	- Build the new container image by using cosign keyless mode (preferred method to use)  or key mode


> Future goals:
> - Visualize code call flow like call graph, context, AST, CFG, PDG, etc., as graph diagrams using code property graph concept and neo4j graph database. Also, show dependencies graph flow from static and run-time data collected by profiling tools & falco, along with vulnerabilities, plus historical data by mapping historical changes in the code flow & packages. Something like Graph Buddy and Context Buddy as IDE plug-ins.
> - Another visualization is by showing graph flow of all the dependencies in the application, containers, k8s manifests, etc., with all the changes happening when scsctl is used for automation.
> - Integration with [deps.dev](https://deps.dev/) API to create graph view of the dependencies.
> - Integration with Qualys, Nessus, Rapid 7, DeepFactor, etc.
> - Productivity and User Experience - Previous & Updated Vulnerability detail views, Display of asset selection rules to view vulnerability details per service/node/cluster/namespace/pod/etc. and also overall view, etc.
> - Risk-based Posture Management - Risk Configuration + Risk Customizations, EPSS factor in risk calculation, etc.
> - Manage Vulnerabilities and Assets - Filter vulnerabilities by asset & vulnerability tags, export vulnerability data in csv or directly generate graphs using clickhouse/cassandra as datasource, Linking of Teams to Apps/Environments/Platforms/Clusters/Vulnerabilities/etc., multi-selection for varieties of filters to visualize the data in different charts, etc.
> - Build features mentioned in these CycloneDX based reports :
	- [CycloneDX BOM server](https://github.com/CycloneDX/cyclonedx-bom-repo-server)
	, [CDXGen](https://github.com/CycloneDX/cdxgen)
	, [CycloneDX Python lib for Programmatic purpose](https://github.com/CycloneDX/cyclonedx-python-lib)
	, [CycloneDX Web Tool](https://github.com/CycloneDX/cyclonedx-web-tool)
	, [SBOM-Utility API platform](https://github.com/cyclonedx/sbom-utility)
	, [eBay SBOM scorecard](https://github.com/eBay/sbom-scorecard)
	, [Agentless Vuln. Scanner - Vuls](https://vuls.io/)
	, [Generate VEX (Vulnerability Exploitability Exchange) CycloneDX documents](https://github.com/madpah/vexy)
	, [openSSF Scorecard API](https://api.securityscorecards.dev/#/)
	, [same as Tally project](https://github.com/jetstack/tally) with openSSF scorecard
	, [SBOM dependency graph diagram](https://github.com/anthonyharrison/sbom2dot) similar to call graph diagram
	, [Transform SBOM contents into Markdown](https://github.com/anthonyharrison/sbom2doc)
	, [Scan K8s with Syft - SBOM Operator](https://github.com/ckotzbauer/sbom-operator)
	, [GitHub Action / Tekton CI steps to show differences in SBOMs](https://github.com/thepwagner/sbom-action)
	, [SBOM publish, verify & share - this is perfect example on how we wanted to build certain feature](https://github.com/interlynk-io)
	

### Usage

Before starting, make sure you have the following installed and configured:

1. Docker - Make sure docker is running, and the image you want to scan is present in the docker daemon
2. Trivy - Trivy will be automatically installed if not present
3. Pyroscope - Pyroscope is up and running, and profiling data is being collected from the application you want to scan. You also need the Pyroscope server URL and the application name
4. ClickHouse (optional) - If you want to save the data collected by SCSCTL for historical analysis purpose, then make sure ClickHouse is up and running and you have the ClickHouse server URL and the database details

   > If you don't want to save the data, then you can skip this step.

   > If you want to save the data, then please set the following environment variables:
   > The database name will be `scsctl`
   >
   > - `CLICKHOUSE_HOST` - The URL of the ClickHouse server
   > - `CLICKHOUSE_USER` - The username of the ClickHouse server
   > - `CLICKHOUSE_PASSWORD` - The password of the ClickHouse server
   > - `CLICKHOUSE_PORT` - The port of the ClickHouse server

### Running the tool

1. Clone the repo
2. pip install -r requirements.txt
3. python setup.py bdist_wheel --universal (This will create a wheel file in the dist folder)
4. Install the wheel file using pip install <wheel file name>
5. Run the tool using `scsctl` command
6. You can also run the tool using `python app.py` without building the wheel file
7. After scanning, you can see the reports or rebuild the docker image from the menu

### Commands

scsctl has the following commands:

- pyroscope_app_name (string) - Pyroscope app name
- docker_image_name (string) - Docker image name
- pyroscope_url (string) - Url for pyroscope
- falco_pod_name (string) - Pod name of falco
- falco_target_deployment_name (string) - Deployment name of falco
- db_enabled (boolean) - To enable db saving
- falco_enabled (boolean) (optional) - To get logs from falco
- docker_file_folder_path (string) (optional) - Dockerfile folder path if you need to rebuild the image
- config_file (optional) (YAML)

> This command will scan the docker image and generate the reports

```shell
scsctl scan --pyroscope_app_name <pyroscope_app_name> --docker_image_name <docker_image_name> --pyroscope_url <pyroscope_url> --docker_file_folder_path <docker_file_folder_path> --falco_pod_name <falco_pod_name> --falco_target_deployment_name <app> --falco_enabled
```

Example:

```shell
scsctl scan --pyroscope_app_name dagflow-api --docker_image_name dagflow-app-with-db-url:latest --pyroscope_url http://localhost:4040 --docker_file_folder_path /home/jegath/Documents/intelops/sps/dagflow/app/ --falco_pod_name falco-mvnmt --falco_target_deployment_name app --falco_enabled
```

> There is also an option to pass a yaml as a config file.

```shell
scsctl scan --config_file ./test.yaml
```

> Sample yaml file

```yaml
pyroscope_app_name: dagflow-api
docker_image_name: dagflow-app-with-db-url:latest
pyroscope_url: http://localhost:4040
falco_pod_name: falco-mvnmt
falco_target_deployment_name: app
db_enabled: true
falco_enabled: true
docker_file_folder_path: /home/jegath/Documents/intelops/sps/dagflow/app/
```

### Running the tool in ci/cd environment

To run scsctl in ci/cd environment,
1. Install scsctl from pypi
2. Run the tool

Example


```yaml
name: scsctl_test
on:
  push:
    branches: [ main ]
jobs:
  container-test-job:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3

    - name: Pull pyroscope/pyroscope:latest image 
      run: docker pull pyroscope/pyroscope:latest

    - name: Install a python cli tool from test pypi  and run it
      run: |
        python -m pip install --upgrade pip
        python -m pip install --upgrade build
        python -m pip install scsctl

    - name: run scsctl tool
      run: |
        scsctl scan --pyroscope_app_name pyroscope.server --docker_image_name pyroscope/pyroscope:latest --pyroscope_url https://369d-111-92-44-131.ngrok-free.app --non_interactive
```
