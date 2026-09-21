{ nixpkgs, common }:
# Component qualification only: real appliance sshd credentials/settings and
# firewall, with VM-generated CA material. No enrollment, installed disk, release
# signing or proof of the final signed appliance's live Q13 lifecycle is implied.
import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, lib, ... }: {
  name = "cybex-james-ssh-certificate-policy";
  nodes = {
    appliance = { config, lib, ... }: {
      imports = [ ../module.nix ];
      services.cybex-james = { enable = true; appliance = common; };
      system.stateVersion = "26.05";
      services.timesyncd.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = "192.168.1.10"; prefixLength = 24; }
      ];
      environment.systemPackages = [ pkgs.python3 pkgs.curl pkgs.iproute2 ];
      systemd.services.qualification-forward-target = {
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8081 --bind 127.0.0.1 --directory /run/forward-target";
          User = "nobody";
        };
      };
    };
    allowed = { lib, ... }: {
      system.stateVersion = "26.05";
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = "192.168.1.20"; prefixLength = 24; }
      ];
      environment.systemPackages = [ pkgs.openssh pkgs.python3 pkgs.curl pkgs.netcat-openbsd ];
    };
    denied = { lib, ... }: {
      system.stateVersion = "26.05";
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = "192.168.1.30"; prefixLength = 24; }
      ];
      environment.systemPackages = [ pkgs.netcat-openbsd ];
    };
  };
  testScript = ''
    import shlex

    start_all()
    for node in (appliance, allowed, denied):
        node.wait_for_unit("multi-user.target")
    appliance.fail("systemctl is-active sshd.service")
    appliance.succeed("getent shadow cybex-support | cut -d: -f2 | grep -qx '!'")

    # The CA and authentication key never leave the allowed VM's private /root
    # directory. Only its public CA enters the separate public HTTP directory.
    allowed.succeed("install -d -m0700 /root/ssh-fixture; install -d -m0755 /run/ca-public")
    allowed.succeed("umask 077; ssh-keygen -q -t ed25519 -N \"\" -f /root/ssh-fixture/ca; ssh-keygen -q -t ed25519 -N \"\" -f /root/ssh-fixture/identity")
    for label, principal, validity, extensions in (
        ("accepted", "qualification-support", "-1m:+5m", "-O permit-agent-forwarding -O permit-port-forwarding"),
        ("wrong", "another-support", "-1m:+5m", "-O permit-agent-forwarding -O permit-port-forwarding"),
        ("expired", "qualification-support", "-2h:-1h", "-O permit-agent-forwarding -O permit-port-forwarding"),
        ("no-forward", "qualification-support", "-1m:+5m", ""),
    ):
        allowed.succeed(f"cp /root/ssh-fixture/identity.pub /root/ssh-fixture/{label}.pub; ssh-keygen -q -s /root/ssh-fixture/ca -I {label} -n {principal} -V {validity} -O clear -O permit-pty {extensions} /root/ssh-fixture/{label}.pub >/dev/null 2>&1")
    allowed.succeed("install -m0644 /root/ssh-fixture/ca.pub /run/ca-public/ca.pub")
    allowed.succeed("systemd-run --unit=qualification-ca-public ${pkgs.python3}/bin/python3 -m http.server 8000 --bind 192.168.1.20 --directory /run/ca-public")
    allowed.wait_for_open_port(8000, addr="192.168.1.20")
    appliance.succeed("curl --noproxy '*' --fail --silent --show-error http://192.168.1.20:8000/ca.pub -o /etc/ssh/cybex-james-ca.pub")
    allowed.succeed("systemctl stop qualification-ca-public")
    appliance.succeed("printf 'qualification-support\\n' > /etc/ssh/cybex-james-principals; chmod 0644 /etc/ssh/cybex-james-ca.pub /etc/ssh/cybex-james-principals")
    appliance.succeed("install -d -m0750 -o root -g cybex-james /var/lib/cybex-james/control; printf '192.168.1.20/32\\n' > /var/lib/cybex-james/control/management-cidrs.txt; chmod 0640 /var/lib/cybex-james/control/management-cidrs.txt")
    appliance.succeed("/usr/lib/cybex-james/cybex-james-firewall")
    appliance.succeed("/usr/lib/cybex-james/cybex-james-firewall")

    # As in the runtime component test, preserve the real evaluated sshd unit
    # command, credentials and config. Remove only fixture-unavailable Requires
    # dependencies after proving missing STATE blocks the ordinary service.
    appliance.succeed("sed '/^Requires=/d' /etc/systemd/system/sshd.service > /run/systemd/system/qualification-sshd.service")
    appliance.succeed("systemctl daemon-reload; systemctl start qualification-sshd.service")
    appliance.succeed("ss -ltn | grep -q ':22 '")
    allowed.succeed("nc -z -w 3 192.168.1.10 22")
    denied.fail("nc -z -w 3 192.168.1.10 22")

    base = "ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=3 -o ConnectionAttempts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i /root/ssh-fixture/identity"
    def ssh(cert="accepted", user="cybex-support", options="", command="true"):
        return f"{base} -o CertificateFile=/root/ssh-fixture/{cert}-cert.pub {options} {user}@192.168.1.10 {shlex.quote(command)}"

    allowed.succeed(ssh(command="test $(id -un) = cybex-support"))
    # Isolate each negative case from OpenSSH's real per-source failure penalty;
    # otherwise throttling can conceal whether the certificate policy rejected it.
    # Reset the fixture unit between cases, including its systemd start counter,
    # instead of disabling either production protection.
    for command in (
        ssh(user="root"), ssh(cert="wrong"), ssh(cert="expired"),
        f"{base} -o CertificateFile=none cybex-support@192.168.1.10 true",
    ):
        appliance.succeed("systemctl reset-failed qualification-sshd.service; systemctl restart qualification-sshd.service")
        rejected = allowed.fail(command + " 2>&1")
        assert "Permission denied (publickey)" in rejected, rejected
    # Check the actual authentication exchange: password must not even be offered.
    appliance.succeed("systemctl reset-failed qualification-sshd.service; systemctl restart qualification-sshd.service")
    allowed.fail("ssh -vv -F /dev/null -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive cybex-support@192.168.1.10 true >/root/ssh-fixture/password.out 2>/root/ssh-fixture/password.log")
    allowed.succeed("grep -Eq 'Authentications that can continue: publickey[[:space:]]*$' /root/ssh-fixture/password.log")
    allowed.fail("grep -Eq 'Next authentication method: (password|keyboard-interactive)' /root/ssh-fixture/password.log")

    appliance.succeed("systemctl reset-failed qualification-sshd.service; systemctl restart qualification-sshd.service")
    appliance.succeed("install -d -m0755 /run/forward-target; printf 'forwarding-fixture-ok\\n' > /run/forward-target/index.html; chmod 0644 /run/forward-target/index.html; systemctl start qualification-forward-target")
    appliance.wait_for_open_port(8081)
    allowed.succeed(ssh(cert="no-forward", command="true"))
    # -W opens a real direct-tcpip channel; the restricted certificate still
    # authenticates but its signed extensions must prohibit this same channel.
    forward = f"{base} -o CertificateFile=/root/ssh-fixture/accepted-cert.pub -W 127.0.0.1:8081 cybex-support@192.168.1.10"
    allowed.succeed(f"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | {forward} | grep -q forwarding-fixture-ok")
    forward_denied = f"{base} -o CertificateFile=/root/ssh-fixture/no-forward-cert.pub -W 127.0.0.1:8081 cybex-support@192.168.1.10"
    allowed.fail(forward_denied + " </dev/null >/root/ssh-fixture/forward.out 2>/root/ssh-fixture/forward.log")
    allowed.succeed("grep -q 'administratively prohibited' /root/ssh-fixture/forward.log")

    allowed.succeed("ssh-agent -a /root/ssh-fixture/agent.sock >/dev/null; SSH_AUTH_SOCK=/root/ssh-fixture/agent.sock ssh-add /root/ssh-fixture/identity >/dev/null 2>&1")
    # IdentityAgent=none in base must not override the requested agent socket:
    # OpenSSH uses the first occurrence. Keep explicit identities for auth.
    agent_base = base.replace("-o IdentityAgent=none", "-o IdentityAgent=/root/ssh-fixture/agent.sock")
    for cert, command in (
        ("accepted", 'test -n "$SSH_AUTH_SOCK" && ssh-add -l >/dev/null'),
        ("no-forward", 'test -z "$SSH_AUTH_SOCK"'),
    ):
        allowed.succeed(f"SSH_AUTH_SOCK=/root/ssh-fixture/agent.sock {agent_base} -A -o CertificateFile=/root/ssh-fixture/{cert}-cert.pub cybex-support@192.168.1.10 {shlex.quote(command)}")

    # Change the protected CIDR source, atomically replace the real nft table,
    # and prove policy reverses for both independent VMs without touching sshd.
    appliance.succeed("printf '192.168.1.30/32\\n' > /var/lib/cybex-james/control/management-cidrs.txt; /usr/lib/cybex-james/cybex-james-firewall")
    allowed.fail("nc -z -w 3 192.168.1.10 22")
    denied.succeed("nc -z -w 3 192.168.1.10 22")
  '';
}) { system = "x86_64-linux"; }
