FROM ubuntu:20.04
#SSH 서버 설치
RUN apt-get update
RUN apt-get install -y openjdk-17-jdk
RUN apt-get install -y openssh-server
RUN apt-get install -y curl zip unzip git vim
RUN curl -s "https://get.sdkman.io" | bash
RUN apt-get update

RUN bash -c "source /root/.sdkman/bin/sdkman-init.sh && sdk install gradle 8.8"

RUN apt-get clean
RUN mkdir /var/run/sshd
#root 암호 설정
RUN echo 'root:1234' | chpasswd
#sshd_config 설정 변경
RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -ri 's/UsePAM yes/#UsePAM yes/g' /etc/ssh/sshd_config
#작업 공간 지정
WORKDIR /work

# JAR 파일을 컨테이너에 복사
# (예: ./build/libs/your-application.jar 경로를 사용한다고 가정)
COPY ./build/libs/ApiGateway-0.0.1.jar /work/ApiGateway-0.0.1.jar

# JAR 파일을 실행
ENTRYPOINT ["java", "-jar", "/work/ApiGateway-0.0.1.jar"]