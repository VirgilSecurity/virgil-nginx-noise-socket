stage('Get nginx sources'){
    node('master'){
        clearContentUnix()
        sh "wget https://nginx.org/download/nginx-1.12.0.tar.gz"
        sh "tar xfz nginx-1.12.0.tar.gz"
        sh "mkdir virgil-nginx-noise-socket"
        dir("nginx-1.12.0/virgil-nginx-noise-socket"){
            checkout scm
        }
        stash excludes: "*.tar.gz", includes: '**', name: 'nginx-source'
    }
}

stage('Build'){
    node("build-docker"){
        docker.image('centos:7').inside("--user root"){
            clearContentUnix()
        }
        unstash "nginx-source"
        docker.image('centos:7').inside("--user root"){
            sh "yum install -y gcc make pcre pcre-devel pcre2 pcre2-devel openssl-devel autoconf automake flex bison git ruby ruby-devel curl libyaml-devel rpm-build wget"
            sh "gem install fpm"
            // build libsodium
            // sh "git clone https://github.com/jedisct1/libsodium.git -b stable"
            sh "wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.13.tar.gz"
            sh "tar xzf libsodium-1.0.13.tar.gz"
            sh "cd libsodium-1.0.13 && ./configure"
            sh "cd libsodium-1.0.13 && make && make check"
            sh "cd libsodium-1.0.13 && make install"
            sh "echo '/usr/local/lib' >> /etc/ld.so.conf.d/libsodium.conf"
            sh "cat /etc/ld.so.conf.d/libsodium.conf"
            sh "ldconfig"
            // sh "ls -la libsodium"
            // sh "ls -la libsodium/src/"
            // sh "ls -la libsodium/src/libsodium"
            // sh "ls -la libsodium/src/libsodium/.libs"
            // sh "cp libsodium/src/libsodium/.libs/libsodium.so.18.3.0 /lib/libsodium.so.18.3.0"
            // sh "ln -s /lib/x86_64-linux-gnu/libsodium.so.18.3.0 /lib/libsodium.so.18"
            // sh "ln -s /lib/x86_64-linux-gnu/libsodium.so.18.3.0 /lib/libsodium.so"
            // sh "cp libsodium/src/libsodium/.libs/libsodium.a /lib/libsodium.a"
            // build noise
            sh "git clone https://github.com/rweather/noise-c.git"
            sh "cd noise-c && autoreconf -i"
            sh "cd noise-c && ./configure --with-openssl --with-libsodium"
            sh "cd noise-c && make"
            sh "cd noise-c && make install"
            sh "cd noise-c && mkdir noise-artifact"
            sh "cd noise-c && export DESTDIR='noise-artifact' && make install"
            sh "ls -la noise-c/include/noise/noise-artifact"
            sh "cd nginx-1.12.0 && ./configure --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --pid-path=/var/run/nginx.pid --lock-path=/var/lock/nginx.lock --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/body --http-proxy-temp-path=/var/lib/nginx/proxy --without-http_fastcgi_module --without-http_uwsgi_module --with-http_stub_status_module --with-http_gzip_static_module --with-http_ssl_module --with-debug --add-module=./virgil-nginx-noise-socket"
            // build nginx
            sh "cd nginx-1.12.0 && make"
            sh "cd nginx-1.12.0 && mkdir nginx-artifact"
            sh "cd nginx-1.12.0 && export DESTDIR='nginx-artifact' && make install"
            sh "cp -r noise-c/include/noise/noise-artifact/* nginx-1.12.0/nginx-artifact/"
            sh "ls -l nginx-1.12.0/nginx-artifact"
            sh "fpm -s dir -t rpm -p ./ -m 'sk@virgilsecurity.com' --description 'Virgil Security Noise Socket nginx with plugin' \
            --rpm-use-file-permissions \
            -n 'virgil-nginx-noise-socket' -v 1.0.${BUILD_NUMBER} -C nginx-1.12.0/nginx-artifact ./"
        }
        stash includes: "*.rpm", name: "nginx-rpm"
    }
}

stage('Deploy artifacts'){
    node('master'){
        dir('nginx-1.12.0/virgil-nginx-noise-socket'){
            dir('ci'){
                unstash 'nginx-rpm'
            }
            sh "ansible-playbook -i ci/nginx-inventory ci/nginx-deploy.yml --extra-vars 'rpm_name=virgil-nginx-noise-socket-1.0.${BUILD_NUMBER}-1.x86_64.rpm'"
            dir('ci'){
                archiveArtifacts("*.rpm")
            }
        }
    }
}

// Utility Functions

def clearContentUnix() {
    sh "rm -fr -- *"
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}
