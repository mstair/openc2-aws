FROM python:3-slim

VOLUME ["/opt/cloudslpf-config"]

# Copy application files
COPY . /tmp/build
WORKDIR /tmp/build

# Clean application
RUN python ./clean.py

# Install application package and its dependencies
RUN pip install --upgrade pip
RUN pip install .
RUN pip install -r requirements.txt

# Cleanup build
RUN rm -rf /tmp/build

################### INSTALLATION END #######################
#
# Run the application.
#
# NOTE: The configuration files for the application must be
#       mapped to the path: /opt/cloudslpf-config
#
# For example, specify a "-v" argument to the run command
# to mount a directory on the host as a data volume:
#
#   -v /host/dir/to/config:/opt/cloudslpf-config
#
ENTRYPOINT ["python", "-m", "cloudslpf", "/opt/cloudslpf-config"]
