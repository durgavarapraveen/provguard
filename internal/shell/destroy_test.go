package shell

import "testing"

func TestDestructiveCommands(t *testing.T) {
	cases := []struct {
		cmd    string
		detail string // "" means no DESTROY sink
	}{
		{"terraform destroy -auto-approve", "terraform_destroy"},
		{"terraform apply -destroy", "terraform_destroy"},
		{"terraform plan", ""},
		{"terraform destroy --help", ""},
		{"pulumi destroy --yes", "pulumi_destroy"},
		{"kubectl -n prod delete ns staging", "kubectl_delete"},
		{"kubectl delete pvc/data-0", "kubectl_delete"},
		{"kubectl delete pods --all", "kubectl_delete"},
		{"kubectl delete pod web-1", ""},
		{"helm uninstall api", "helm_uninstall"},
		{"docker system prune -a", "docker_system_prune"},
		{"docker volume rm pgdata", "docker_volume_rm"},
		{"docker compose down -v", "docker_compose_down"},
		{"docker compose down", ""},
		{"docker rm -f web", ""},
		{"aws ec2 terminate-instances --instance-ids i-1", "cloud_delete:aws"},
		{"aws dynamodb delete-table --table-name t", "cloud_delete:aws"},
		{"aws s3 rm s3://bucket --recursive", "cloud_delete:aws"},
		{"aws s3 rb s3://bucket", "cloud_delete:aws"},
		{"aws s3 ls", ""},
		{"gcloud compute instances delete vm1", "cloud_delete:gcloud"},
		{"az group delete -n rg", "cloud_delete:az"},
		{"gsutil rm -r gs://bucket", "cloud_delete:gsutil"},
		{`psql -c "DROP TABLE users"`, "db_drop:psql"},
		{`mysql -e "delete from users;"`, "db_drop:mysql"},
		{`psql -c "DELETE FROM users WHERE id=1"`, ""},
		{`psql -c "select 1"`, ""},
		{"redis-cli FLUSHALL", "db_drop:redis-cli"},
		{`mongosh --eval "db.dropDatabase()"`, "db_drop:mongosh"},
		{"dropdb app", "db_drop:dropdb"},
		{"dd if=x.img of=/dev/sda", "dd_device"},
		{"dd if=/dev/zero of=/dev/null bs=1M count=1", ""},
	}
	for _, c := range cases {
		got := ""
		for _, s := range Analyze(c.cmd, Bash).Sinks {
			if s.Class == Destroy {
				got = s.Detail
			}
		}
		if got != c.detail {
			t.Errorf("%s: DESTROY %q, want %q", c.cmd, got, c.detail)
		}
	}
	// PowerShell disk cmdlets.
	if !Analyze("Clear-Disk -Number 1 -RemoveData", PowerShell).Has(Destroy) {
		t.Error("Clear-Disk: no DESTROY sink")
	}
}
