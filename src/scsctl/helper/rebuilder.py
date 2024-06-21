import os
import time
from kubernetes import client, config
import subprocess

def build_image_with_kaniko_and_download(dockerfile_path, image_name, image_tag):
    """Build a Docker image using Kaniko and download it as a tar file.

    Args:
        dockerfile_path (str): Absolute path to the Dockerfile.
        image_name (str): Name of the Docker image.
        image_tag (str): Tag for the Docker image.

    Returns:
        None
    """
    # Load the Kubernetes configuration
    config.load_kube_config()

    # Create a Kubernetes API client
    api_client = client.ApiClient()
    batch_api = client.BatchV1Api(api_client)
    core_api = client.CoreV1Api(api_client)

    # Get the build context directory from the Dockerfile path
    build_context = os.path.dirname(dockerfile_path)

    os.chmod(build_context, 0o777)

    # Create a Kaniko job to build the Docker image
    job_name = "kaniko-build-job"
    job = client.V1Job(
        metadata=client.V1ObjectMeta(name=job_name),
        spec=client.V1JobSpec(
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(labels={"app": "kaniko-builder"}),  # Add selector label
                spec=client.V1PodSpec(
                    containers=[
                        client.V1Container(
                            name="kaniko",
                            image="gcr.io/kaniko-project/executor:latest",
                            args=[
                                "--dockerfile=%s" % os.path.basename(dockerfile_path),
                                f"--context={build_context}",
                                "--destination=%s:%s" % (image_name, image_tag),
                                "--no-push",
                                f"--tarPath=/context/{image_name}_{image_tag}.tar"
                            ],
                            volume_mounts=[
                                client.V1VolumeMount(
                                    name="context-volume",
                                    mount_path="/context",
                                )
                            ],
                        ),
                    ],
                    volumes=[
                        client.V1Volume(
                            name="context-volume",
                            host_path=client.V1HostPathVolumeSource(
                                path="/tmp/proact_temp_repo",
                                type="DirectoryOrCreate",
                            )
                        )
                    ],
                    restart_policy="Never",
                    affinity=client.V1Affinity(
                        node_affinity=client.V1NodeAffinity(
                            required_during_scheduling_ignored_during_execution=client.V1NodeSelector(
                                node_selector_terms=[
                                    client.V1NodeSelectorTerm(
                                        match_expressions=[
                                            client.V1NodeSelectorRequirement(
                                                key="proact-node",
                                                operator="In",
                                                values=["true"]
                                            )
                                        ]
                                    )
                                ]
                            )
                        )
                    )
                )
            )
        )
    )

     # Delete the job if it already exists
    try:
        batch_api.delete_namespaced_job(name=job_name, namespace="default")
    except client.rest.ApiException as e:
        if e.status != 404:
            print(f"Failed to delete job '{job_name}': {e}")

    # Create the Kaniko job
    batch_api.create_namespaced_job(body=job, namespace="default")
    print(f"Kaniko job '{job_name}' created to build image '{image_name}:{image_tag}'")

    # # Wait for the job to complete
    # while True:
    #     time.sleep(5)
    #     job_status = batch_api.read_namespaced_job_status(job_name, namespace="default")
    #     if job_status.status.succeeded is not None and job_status.status.succeeded > 0:
    #         break
    #     elif job_status.status.failed is not None and job_status.status.failed > 0:
    #         print(f"Kaniko job '{job_name}' failed to build image '{image_name}:{image_tag}'")
    #         break

    # # Once the job is completed, query for the pod with the selector label
    # pods = core_api.list_namespaced_pod(namespace="default", label_selector="app=kaniko-builder")
    # if pods.items:
    #     pod_name = pods.items[0].metadata.name
    #     print(f"Rebuild logs from pod ': {pod_name}")
    #     # Get logs from the pod
    #     logs = core_api.read_namespaced_pod_log(name=pod_name, namespace="default")
    #     print(logs)
    # else:
    #     print("No pod found with selector 'app=kaniko-builder'")

    # Delete the Kaniko job
    batch_api.delete_namespaced_job(name=job_name, namespace="default")
    return f"{image_name}_{image_tag}"

# dockerfile_path = "/home/jegath/Documents/work/scsctl/testDockerfile"
# build_image_with_kaniko_and_download(dockerfile_path, "rebuilded-image", "latest")


from datetime import datetime

def getTimestamp():
    # Get the current time
    now = datetime.now()

    # Extract and format the components
    month = now.strftime("%m")  # Month
    day = now.strftime("%d")    # Day
    year = now.strftime("%Y")   # Year
    minute = now.strftime("%M") # Minutes
    second = now.strftime("%S") # Seconds
    millisecond = now.strftime("%f")[:3]  # Milliseconds (first 3 digits of microsecond part)
    nanosecond = f"{now.microsecond * 1000:09d}"[-3:]  # Nanoseconds (last 3 digits)

    # Combine to the desired format
    date_time_str = f"{month}{day}{year}{minute}{second}{millisecond}{nanosecond}"
    
    return date_time_str

def build_image_with_buildah(docker_file, image_name, repo_dir):
    image_tag = getTimestamp()
    subprocess.run(["buildah", "build", "-f", docker_file, "-t", f"{image_name}:{image_tag}", repo_dir])
    return f"{image_name}:{image_tag}"

def copy_and_build_image_with_buildah(dockerfile_path, image_name):
    image_tag = getTimestamp()
    # Check if dockerfile_path is a github repo url or a local path
    if dockerfile_path.startswith("http://") or dockerfile_path.startswith("https://"):
        # Clone the repository to a temporary directory
        repo_dir = "/tmp/proact_temp_repo"
        subprocess.run(["git", "clone", dockerfile_path, repo_dir])
        # Get the Dockerfile path from the repository
        docker_file = os.path.join(repo_dir, "Dockerfile")
        # Build the image using Buildah
        subprocess.run(["buildah", "build", "-f", docker_file, "-t", f"{image_name}:{image_tag}", repo_dir])
        # Remove the repository directory
        subprocess.run(["rm", "-rf", repo_dir])
    else:
        # Build the image using Buildah
        # Copy the Dockerfile folder to /tmp/proact_temp_repo
        repo_dir = "/tmp/proact_temp_repo"
        base_dir = os.path.dirname(dockerfile_path)
        file_name = os.path.basename(dockerfile_path)
        subprocess.run(["cp", "-r", base_dir, repo_dir])
        docker_file = os.path.join(repo_dir, file_name)
        subprocess.run(["buildah", "build", "-f", docker_file, "-t", f"{image_name}:{image_tag}", repo_dir])
        # Remove the repository directory if exists
        subprocess.run(["rm", "-rf", repo_dir])

    print(f"Image '{image_name}:{image_tag}' built successfully")