docker.run(
    image="your_image",
    cap_add=["NET_ADMIN"],
    security_opt=["seccomp:unconfined"]
)