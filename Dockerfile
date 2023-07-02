FROM python:latest

RUN mkdir /opt/grinder

COPY . /opt/grinder

RUN ls -l /opt/grinder
RUN cat /opt/grinder/config.py

WORKDIR /opt/grinder

RUN apt update && apt install python3 python3-pip patool -y

RUN pip3 install -r requirements.txt

RUN python3 setup.py

ENTRYPOINT ["python3", "grinder.py"]
CMD [""]
