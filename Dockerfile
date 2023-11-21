FROM pwncollege_challenge

RUN pip install jinja2 pyastyle

RUN mkdir /pwnshop
WORKDIR /pwnshop

RUN echo -n 'FLAG{TEST}' > /flag

ADD . .
RUN pip install -e .
