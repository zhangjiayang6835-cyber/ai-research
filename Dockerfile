# Use an official base image
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Copy the application code
COPY. /app

# Install necessary packages
RUN apk add --no-cache python3

# Create a non-root user
RUN adduser -D appuser

# Switch to the non-root user
USER appuser

# Expose the port your application runs on
EXPOSE 8080

# Command to run the application
CMD ["python3", "app.py"]