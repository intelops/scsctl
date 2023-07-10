# scsctl
> We are continuously adding the listed features

CLI/CI Tool for Automating Vulnerability Management for Enhancing Software Supply Chain Security Measures.

### Features
- Integration with other Tools & Platforms:
	- Trivy
	- Grype
	- Syft
	- CycloneDX
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
- Integration with DB(s):
	- ClickHouse
 	- Cassandra 
- Reports: (dependency packages and SBOM/gitbom reports)
	- SBOM
	- Report using Profiling tools Data
	- Report using Falco security tool using its run-time dependency packages tracking policy feature
	- Unnecessary packages used in container image by observing the run-time usage 
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


### Usage

Before starting, make sure you have the following installed and configured:

1. Docker - Make sure docker is running, and the image you want to scan is present in the docker daemon
2. Trivy - Trivy will be automatically installed if not present
3. Pyroscope - Pyroscope is up and running, and profiling data is being collected from the application you want to scan. You also need the Pyroscope server URL and the application name
4. ClickHouse (optional) - If you want to save the data collected by SCSCTL for historical analysis purpose, then make sure ClickHouse is up and running and you have the ClickHouse server URL and the database details
	> If you don't want to save the data, then you can skip this step.

	> If you want to save the data, then please set the following environment variables:
	The database name will be `scsctl`
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
> This command will scan the docker image and generate the reports
```shell
scsctl scan --docker_image_name <docker-image-name> --docker_file_folder_path <docker-file-folder-path> --pyroscope_url <pyroscope-url> --pyroscope_app_name <pyroscope-app-name>
```
Example:
```shell
scsctl scan --docker_image_name test:latest --docker_file_folder_path /home/test --pyroscope_url http://localhost:4040 --pyroscope_app_name test
```

