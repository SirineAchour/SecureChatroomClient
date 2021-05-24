FROM python

RUN curl https://bootstrap.pypa.io/pip/2.6/get-pip.py --output get-pip.py && \
    python2 get-pip.py

WORKDIR /app

COPY . .

RUN pip2 install -r requirements.txt

CMD ["usage: docker run -it <image> python2 client.py <ip> <port> <password> <username>"]

ENTRYPOINT ["echo"]

