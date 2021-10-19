resource "aws_instance" "some_name" {
  ami                    = "ami-blah"
  instance_type          = "m4.10xlarge"
  }

  tags = merge(
    var.tags,
    {
      Name = "name_name_name"
    },
  )
}
