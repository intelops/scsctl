import os
import time
import tarfile
from kubernetes import client, config, watch

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
                                "--context=/context",
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
                        )
                    ],
                    volumes=[
                        client.V1Volume(
                            name="context-volume",
                            host_path=client.V1HostPathVolumeSource(
                                path=build_context,
                                type="Directory",
                            )
                        )
                    ],
                    restart_policy="Never",
                )
            )
        )
    )

    # Create the Kaniko job
    batch_api.create_namespaced_job(body=job, namespace="default")
    print(f"Kaniko job '{job_name}' created to build image '{image_name}:{image_tag}'")

    # Wait for the job to complete
    while True:
        time.sleep(5)
        job_status = batch_api.read_namespaced_job_status(job_name, namespace="default")
        if job_status.status.succeeded is not None and job_status.status.succeeded > 0:
            break
        elif job_status.status.failed is not None and job_status.status.failed > 0:
            print(f"Kaniko job '{job_name}' failed to build image '{image_name}:{image_tag}'")
            break

    # Once the job is completed, query for the pod with the selector label
    pods = core_api.list_namespaced_pod(namespace="default", label_selector="app=kaniko-builder")
    if pods.items:
        pod_name = pods.items[0].metadata.name
        print(f"Rebuild logs from pod ': {pod_name}")
        # Get logs from the pod
        logs = core_api.read_namespaced_pod_log(name=pod_name, namespace="default")
        print(logs)
    else:
        print("No pod found with selector 'app=kaniko-builder'")

    # Delete the Kaniko job
    batch_api.delete_namespaced_job(name=job_name, namespace="default")

# dockerfile_path = "/home/jegath/Documents/work/scsctl/testDockerfile"
# build_image_with_kaniko_and_download(dockerfile_path, "rebuilded-image", "latest")
