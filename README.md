# scsctl
Tool for automating Vulnerability Risk Management for enhancing Software Supply Chain Security Measures.

### Features
- Integrations:
	- Trivy
	- Grype
	- Syft
	- CycloneDX
	- Snyk
	- Pyroscope
	- Parca
	- Falco Security
	- KubViz
	- Dive
	- Skopeo
	- SlimToolKit 
- DB:
	- ClickHouse
- Reports: (dependency packages and SBOM reports)
	- SBOM
	- Profiling tools Data based report
	- Falco tool based report
	- Unnecessary packages used
- Automations:
	- Report unused packages with full details 
	- Remove unused dependencies from code base 
	- Generate new container image with only used dependencies 
	- Update the versions of the dependencies based on wherever the packages are available (opensource or private arti-factory) and then generate new container
	- Generate new containers using Alpine as first option and WolfiLinux as 2nd option for distroless images


### Usage

Before starting make sure you have the following installed and configured:

1. Docker - Make sure docker is running and the image you want to scan is present in the docker daemon
2. Trivy - Trivy will be automatically isntalled if not present
3. Pyroscope - Pyroscope is up and running and profiling data is being collected from the application you want to scan. You also need the pyroscope server url and the application name
4. ClickHouse (optional) - If you want to save the data, then make sure clickHouse is up and running and you have the clickhouse server url and the database name
	> If you don't want to save the data, then you can skip this step.

	> If you want to save the data, then please set the following environment variables:
	Database name will be `scsctl`
	> - `CLICKHOUSE_HOST` - The url of the clickhouse server
	> - `CLICKHOUSE_USER` - The username of the clickhouse server
	> - `CLICKHOUSE_PASSWORD` - The password of the clickhouse server
	> - `CLICKHOUSE_PORT` - The port of the clickhouse server
	
### Running the tool

1. Clone the repo
2. pip install -r requirements.txt
3. python setup.py bdist_wheel --universal (This will create a wheel file in the dist folder)
4. Install the wheel file using pip install <wheel file name>
5. Run the tool using `scsctl` command
6. You can also run the tool using `python app.py` without building the wheel file
7. After scanning you can see the reports or rebuild the docker image from the menu


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

