FROM python:3.12-slim

WORKDIR /app

# Copy all source files from the 6_eyes directory to the workdir
COPY 6_eyes/ .

# Ensure Reports directory exists inside the container
RUN mkdir -p Reports

# Run the scanner script by default
CMD ["python", "main.py"]
