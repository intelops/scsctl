# scsctl
Tool for automating Vulnerability Risk Management and Software Supply Chain Security Measures

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


