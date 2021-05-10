__<h1>Integration of AWS, Terraform and Jenkins</h1>__

![Terraform_Jenkins_AWS](https://miro.medium.com/max/875/1*Y2i80oe9bAVP-HJepILKkg.png)<br>

<br>
<h2>What is Terraform ?</h2>
<p><b>Terraform</b> is an open-source infrastructure as code software tool created by <b>HashiCorp</b>. It enables users to define and provision a datacenter infrastructure using a high-level configuration language known as <b>HashiCorp Configuration Language</b>, or optionally <b>JSON</b>.</p>
<p>The current project has been divided into two parts i.e. first part involves AWS and Terraform and second part involves integration of the the setup with Jenkins.</p>

<h2>Part 1 : AWS and Terraform</h2>
<p>First of all, we need to specify the provider to be used in our Terraform Code , in our case we are using <b>AWS</b>, thereby we need to specify the same , I have specified the access key, secret key , though you can create a <b>profile</b> and specify the same for security purpose and region under which we are creating the infrastructure.</p><br>

```hcl
provider "aws" {
  region     = "ap-south-1"
  access_key = "****************"
  secret_key = "****************"
}
```

<p><b>Note</b> :- Never upload the Terraform Code with credentials explicitly specified on any public platform like GitHub and many more as it would pose huge risk to your account’s security.</p><br>

<p align="center"><b>. . .</b></p><br>


<p>Here, availability zone “ap-south-1c ” is blacklisted as the instance type (which is specified in AWS Instance Resource) is not available in this particular Availability Zone.</p><br>

```hcl
data "aws_availability_zones" "task_az" {
  exclude_names = ["ap-south-1c"]
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p>Instead of manually creating key in AWS console and then specifying it directly in our AWS Instance, automation in key generation could be done by creating a <b>TLS Private Key</b> and here we use <b>RSA</b> algorithm for private key generation which is required for generation of key pair required for accessing <b>EC2</b> Instance, under aws_key_pair resource, <b>public_key</b> has been specified whose value are obtained from tls_private_key resource.</p><br>

```hcl
resource "tls_private_key" "tlskey" {
  algorithm = "RSA"
}

resource "aws_key_pair" "tkey" {
  key_name   = "task-key"
  public_key = tls_private_key.tlskey.public_key_openssh
}
```

<p><b>Note</b> :-If not specified , the size of TLS private key generated using RSA algorithm is 2048 bits.</p><br>

<p align="center"><b>. . .</b></p><br>

<p>For purpose of automation, we can generate <b>VPC</b> using Terraform resource known as <b>aws_pc</b> , here specifying <b>CIDR Block</b> (a set of IP Addresses used for creating unique identifiers for the network and individual devices) is mandatory to be specified.</p><br>

```hcl
resource "aws_vpc" "vpc" {
  cidr_block = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    "Name" = "task_vpc"
  }
}
```

<br>
<p><b>Subnet</b> defines a range of IP addresses under VPC and could be created using Terraform resource known as <b>aws_subnet</b>, the two parameters that needs to be specified are <b>vpc_id</b> (we get those from aws_vpc resource created before) and <b>cidr_block</b> , also for purpose of Public IP creation which would be useful for SSH connection to <b>EC2</b> Instance, the <b>map_public_ip_on_launch</b> has been set to true .</p>
<p>Also. first availability zone excluding the one that has been blacklisted is also specified.</p>

```hcl
resource "aws_subnet" "subnet_public" {
  vpc_id = aws_vpc.vpc.id
  cidr_block = "10.1.0.0/16"
  map_public_ip_on_launch = "true"
  availability_zone = data.aws_availability_zones.task_az.names[0]
  tags = {
    "Name" = "task_subnet"
  }
}
```

<br>
<p><b>Internet Gateway</b> performs <b>network address translation (NAT)</b> for EC2 instances which have been assigned public IPv4 addresses and could be generated using Terraform resource known as <b>aws_internet_gateway</b> and the required parameter in this case is <b>vpc_id</b> that could be obtained by aws_vpc resource created before .</p>

```hcl
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    "Name" = "task_ig"
  }
}
```

<br>
<p>VPC consist of an implicit router and <b>Route Table</b> is used to control the direction of network traffic and could be generated using Terraform resource known as <b>aws_route_table</b> and the required parameters are <b>vpc_id</b> from aws_vpc resource , <b>route</b> is optional and is used for specifying a list of route objects , if used, the required parameter in the same are <b>cidr_block</b> .</p>

```hcl
resource "aws_route_table" "rtb_public" {
  vpc_id = aws_vpc.vpc.id
  route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
     "Name" = "task_route"
  }
}
```

<br>
<p><b>Subnet</b> in VPC must be associated with <b>Route Table</b> as it controls the routing of Subnet and could be generated using Terraform resource known as <b>aws_route_table_association</b> and the required parameters are <b>route_table_id</b> that could be obtained from Route Table generated in <b>aws_route_table</b> resource above, also <b>subnet_id</b> has been specified whose value we get from aws_subnet resource above.</p>

```hcl
resource "aws_route_table_association" "rta_subnet_public" {
  subnet_id      = aws_subnet.subnet_public.id
  route_table_id = aws_route_table.rtb_public.id
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>Security Group</b> in AWS is used for controlling inbound and outbound traffic and could be be generated using Terraform resource known as <b>aws_security_group</b> and under it ingress and egress is optional but could be specified as per need , in our case we have specified for port <b>22</b> with <b>TCP</b> Protocol for enabling SSH connection ,also we have specified port <b>80</b> for enabling HTTP connection and in case of <b>ingress</b> , -1 is specified in <b>egress</b> that indicates all protocols , under ingress and egress, the required parameters are from_port, to_port and protocol .</p><br>
<p><b>Ingress</b> is used for specifying inbound rules which defines the traffic allowed in the EC2 instances and on which ports whereas <b>Egress</b> is used for specifying outbound rules which defines the traffic allowed to leave the EC2 instances on which ports and to which destinations.</p>

```hcl
resource "aws_security_group" "sg_80" {
  name = "sg_80"
  vpc_id = aws_vpc.vpc.id
  
  ingress {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { 
    Name = "task_sg"
  }
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>EC2 Instances</b> provides a balance of compute, memory and networking resources and could be generated using Terraform resource known as <b>aws_instance</b> and the required parameters are <b>ami</b> and <b>instance_type</b>.</p>
<p><b>AMI</b> or <b>Amazon Machine Images</b> provides the information required for launching an instance whereas instance type which has been predefined in this case i.e. <b>“t2.micro”</b> is the combination of CPU, Memory, Storage and Networking Capacity as per requirements of the users or clients .</p>
<p>Also, <b>availability_zone</b>, <b>key_name</b>, <b>subnet_id</b> and <b>vpc_security_group_ids</b> has been specified whose values are obtained from data i.e. aws_availability_zones and resources i.e. aws_key_pair, aws_subnet and aws_security_group respectively .</p><br>

```hcl
resource "aws_instance"  "myinstance"  {
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  availability_zone = data.aws_availability_zones.task_az.names[0]
  key_name      = aws_key_pair.tkey.key_name
  subnet_id = aws_subnet.subnet_public.id
  vpc_security_group_ids = [ aws_security_group.sg_80.id ]
  
  tags = {
    Name = "tfos"
  }
} 
```

<br>

<p>After launching the EC2 instance , setup of <b>provisioner</b> and <b>connection</b> is done under <b>null resource</b> as both of them needs to be declared inside resource or in case of connection, it could be declared under provisioner as well. In connection, <b>type</b> ,<b>user</b>, <b>private key</b> is defined (could be obtained from tls_private_key resource) and <b>host</b>(public IP which could be obtained from aws_instance resource) and it depends on EC2 Instance created using aws_instance resource.</p>
<p>After the connection is set up, set up for project inside the instance could be done using <b>“remote-exec”</b> provisioner , under which installation of httpd and git takes place,and then httpd server is started.</p>

```hcl
resource "null_resource" "op_after_creation"  {

  depends_on = [
    aws_instance.myinstance
  ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.tlskey.private_key_pem
    host     = aws_instance.myinstance.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd"
    ]
  }  
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>EBS Volume</b> is a durable, block-level storage that could be attached to EC2 instances , also it protects in case of failure of single component and could be generated from Terraform resources known as <b>aws_ebs_volume</b> and required parameter is <b>availability_zone</b> which could be obtained from EC2 instances generated using aws_instance resource and it depends on null resource i.e. op_after_creation, here size is defined in <b>GiBs</b> and in this case it is 2 GiBs .</p><br>

```hcl
resource "aws_ebs_volume" "myebs" {
  depends_on = [
    null_resource.op_after_creation
  ]
  availability_zone = aws_instance.myinstance.availability_zone
  size              = 2

  tags = {
    Name = "webPageStore"
  }
}
```

<br>
<p><b>EBS Volume</b> could be attached to the <b>EC2 Instance</b> using Terraform resource known as <b>aws_volume_attachment</b> which depends on aws_ebs_volume resource and the required parameters are <b>device_name</b> whose value in this case is <b>“/dev/sdf”</b> , <b>volume_id</b> whose value could be obtained from <b>EBS Volume</b> created using aws_ebs_volume resource and <b>instance_id</b> whose value could be obtained using EC2 Instance created using aws_instance.</p>
<p><b>Note :-</b> Here, the reason behind <b>force_detach</b> being true is due to the absence of partitioning of <b>EBS Volume</b> , since the absence of partitioning results in difficulty when destroying the EBS Volume while destroying the infrastructure,though it is not a good practice as it results in data loss .</p>

```hcl
resource "aws_volume_attachment" "ebs_att" {
  depends_on = [
    aws_ebs_volume.myebs
  ]
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.myebs.id
  force_detach = true
  instance_id = aws_instance.myinstance.id
}
```

<br>
<p>As soon as attachment of EBS Volume to EC2 Instance takes place, execution of <b>null_resource</b> i.e. <b>op_after_attach</b> starts as it depends on aws_volume_attachment resource, connection setup is similar to the one created in the previous null_resource , here usage of <b>“remote-exec”</b> provisioner is done as well but the setup is different i.e., the EBS Volume attached to the EC2 Instance is formatted and then mounted to Document Root of <b>httpd</b> server i.e., <b>/var/www/html</b>.</p>
<p>After which, all the content present inside html directory as git clone doesn’t clone the respective repository if the target directory consist of any file or directory.</p>

```hcl
resource "null_resource" "op_after_attach"  {

  depends_on = [
    aws_volume_attachment.ebs_att
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.tlskey.private_key_pem
    host     = aws_instance.myinstance.public_ip
  }

  provisioner "remote-exec" {
      inline = [
        "sudo mkfs.ext4  /dev/xvdf",
        "sudo mount  /dev/xvdf  /var/www/html",
        "sudo rm -rf /var/www/html/*",
        "sudo git clone https://github.com/satyamcs1999/terraform_aws_jenkins.git /var/www/html/"
     ]
  }
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>VPC Endpoints</b> ensures that the data between <b>VPC</b> and <b>S3</b> is transferred within Amazon Network , thereby helps in protecting instances from internet traffic and it could be generated using Terraform resources known as <b>aws_vpc_endpoint and the required parameters are <b>service_name</b> and <b>vpc_id</b> .</p>
<p><b>service_name</b> should be specified in the format <b> “com.amazonaws._region_._service_” </b> whereas the value of <b>vpc_id</b> is obtained from the aws_vpc resource generated above.</p><br>
  
```hcl
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.ap-south-1.s3"
}
```

<br>
<p><b>VPC Endpoints</b> are associated with <b>Route Tables</b> and the reason for the same is that the traffic from instances in the subnet could be routed through the endpoint and this association could be generated using Terraform resource known as <b>aws_vpc_endpoint_route_table_association</b> and the required parameters are <b>route_table_id</b> and <b>vpc_endpoint_id</b> , whose value could be obtained from aws_route_table and aws_vpc_endpoint respectively .</p>

```hcl
resource "aws_vpc_endpoint_route_table_association" "verta_public" {
  route_table_id  = aws_route_table.rtb_public.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}
```

<br>

<p><b>S3</b> , an abbreviation of <b>Simple Storage Service</b> is a public cloud storage resource , an object level storage and provides S3 <b>buckets</b> , which are similar to file folders , consisting of data and its metadata. It could be generated using Terraform resource known as <b>aws_s3_bucket</b> and it depends on null_resource i.e, op_after_attach and there are as such no required parameters except if website is used , under which <b>index_document</b> is a required parameter.</p>
<p>In this case, <b>“t1-aws-terraform”</b> has been declared as bucket , <b>acl</b> i.e. <b>Access Control Lists</b> for bucket has been set to <b>“public-read ”</b>, <b>region</b> has been specified <b>“ap-south-1”</b> and <b>force_destroy</b> has been set to true so as to delete bucket with objects within it without error. Under website, the <b>index_document</b> has been set to “index.html”.</p>

```hcl
resource "aws_s3_bucket" "task_bucket" {

  depends_on = [
   null_resource.op_after_attach
  ]
  bucket = "t1-aws-terraform"
  acl    = "public-read"
  region = "ap-south-1"
  force_destroy = "true"
  website{
    index_document = "index.html"
  }

  tags = {
    Name = "t1-terraform"
  }
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>CodePipeline</b> is a fully managed continuous delivery service that helps in automating the release pipeline and could be generated using Terraform resource known as <b>aws_codepipeline</b> and the required parameters are <b>name</b> , i.e., task_codepipeline in this case , <b>role_arn</b> (it grants AWS CodePipeline permission to make calls on behalf of AWS services), <b>artifact_store</b> and <b>stage</b>(at least two).</p>
<p>Under artifact_store, the required parameters are location whose values could be obtained from aws_s3_bucket and type which is in this case ,<b>S3</b>.</p>
<p>Under stage , the required parameters are name and action , name in this case is <b>“Source”</b> and <b>“Deploy”</b>, under action , details of both Source and Deploy i.e.,the required parameters are <b>name</b>, <b>category</b>, <b>owner</b>, <b>provider</b> and <b>version</b> . Also in this case , <b>input_artifacts</b> and <b>output_artifacts</b> has been specified in “Deploy” and “Source” stage respectively.</p>
<p>This overall setup has been done for creating a continuous delivery pipeline between <b>GitHub repo</b> and <b>S3 bucket</b> and and accordingly values has been provided to the parameters of actions .</p>
<p><b>Note :-</b> The recommended policy for providing <b>role_arn</b> parameter to grant someone to make call on behalf on AWS is <b>AdministratorAccess</b>.</p>

```hcl
resource "aws_codepipeline" "task_codepipeline" {
   name = "task_codepipeline"
   role_arn = "arn:aws:iam::**********:role/sats"
   artifact_store {
    location = aws_s3_bucket.task_bucket.bucket
    type = "S3"
  }
  stage {
    name = "Source"
    
    action {
      name = "Source"
      category = "Source"
      owner = "ThirdParty"
      provider = "GitHub"
      version = "1"
      output_artifacts = ["source_output"]
      
      configuration = {
        Owner = "satyamcs1999"
        Repo = "terraform_aws_jenkins"
        Branch = "master"
        OAuthToken = "****************************"
      }
    }
  }
  
  stage {
    name = "Deploy"

    action {
      name = "Deploy"
      category = "Deploy"
      owner = "AWS"
      provider = "S3"
      version = "1"
      input_artifacts = ["source_output"]

      configuration = {
        BucketName = "t1-aws-terraform"
        Extract = "true"
      }
    }
  }
}
```

<br>

<p><b>Waiting time</b> between two resources could be generated using Terraform resource known as <b>time_sleep</b> and it has no required parameter as such. In our case , waiting time could be generated using <b>create_duration</b> parameter and it depends on execution of aws_codepipeline.</p>
<p>The reason behind creation of waiting time is due to time it takes for S3 to replicate the data across <b>multiple servers</b> , if the objects within the bucket is accessed before the replication completes, it would show an error like <b>“NoSuchKey”</b> error.</p>

```hcl
resource "time_sleep" "waiting_time" {
  depends_on = [
    aws_codepipeline.task_codepipeline
  ]
  create_duration = "5m" 
}
```

<br>
<p>As soon as <b>waiting time</b> is over , <b>“local-exec”</b> provisioner enables execution in local system , and in this case , <b>AWS CLI</b> command for making a specific object publicly accessible is performed as the public access to bucket doesn’t ensure public access to the objects within it , so to make a object publicly accessible , the permission has to be provided separately for the object as well, in our case , the object <b>“freddie_mercury.jpg”</b> has been provided <b>“public-read”</b> access.</p>

```hcl
resource "null_resource" "codepipeline_cloudfront" {
   
  depends_on = [
    time_sleep.waiting_time 
  ]
  provisioner "local-exec" {
    command = "/usr/local/bin/aws s3api put-object-acl  --bucket t1-aws-terraform  --key freddie_mercury.jpg   --acl public-read"
  }
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>CloudFront</b> is a fast <b>Content Delivery Network (CDN)</b> for secure delivery of data, videos, application and APIs to customers globally with low latency and high transfer speed and could be generated using Terraform resource known as <b>aws_cloudfront_distribution</b> and the required parameters are <b>default_cache_behavior</b>, <b>enabled</b>, <b>origin</b>, <b>restrictions</b> and <b>viewer_certificate</b> and it depends on complete execution of null_resource i.e., codepipeline_cloudfront, alongside the required parameter, the <b>is_ipv6_enabled</b> is set to “true” thereby enabling <b>IPv6</b> for distribution.</p>
<p>Under <b>origin</b> , <b>domain_name</b> whose value could be obtained from aws_s3_bucket and <b>origin_id</b> of the format <b>“S3-<bucket name>”</b> and both of them are required parameters ,enabled is set to “true” to enable the acceptance of end user requests for content.</p>
<p>Under <b>default_cache_behavior</b> , the required parameters are <b>allowed_methods</b> which specifies the <b>HTTP</b> methods CloudFront would process and forward it to Amazon S3, <b>cached_methods</b> which caches the response to requests using the specified HTTP methods, <b>target_origin_id</b> that is used to specify the origin the CloudFront would route request to and it’s format is same as <b>origin_id</b> ,<b>forwarded_values</b> that specifies the handling of query strings , cookies and headers by CloudFront and under forwarded_values , the required parameters are <b>cookies</b> which specifies how CloudFront handles cookies and <b>query_string</b> that indicates if the query string needs to be forwarded to the origin using CloudFront and last required parameter under default cache behavior is <b>viewer_protocol_policy</b> that specifies the protocol that users could use to access the files in the origin specified by target_origin_id and matches the path pattern.</p>
<p>Alongside the required parameters in <b>default_cache_behaviour</b>, <b>min_ttl</b>, <b>max_ttl</b> and <b>default_ttl</b> has been used which specifies the minimum,maximum and default <b>TTL(Time to Live)</b> for the cached content.</p>
<p>Under <b>restrictions</b>, there is another sub-resource known as <b>geo_restriction</b> under which the required parameter is <b>restriction_type</b> which helps in restricting distribution of content by country.</p>
<p>Under <b>viewer_certificate</b>, <b>cloudfront_default_certificate</b> is set to “true” which enables the viewers to use HTTPS to request the objects .</p>

```hcl
resource "aws_cloudfront_distribution" "task_cloudfront_distribution" {
  depends_on = [
    null_resource.codepipeline_cloudfront  
  ]
  origin {
    domain_name = aws_s3_bucket.task_bucket.bucket_domain_name
    origin_id = "S3-t1-aws-terraform"
  }
  
  enabled = true
  is_ipv6_enabled = "true"

  default_cache_behavior {
    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods = ["GET", "HEAD","OPTIONS"]
    target_origin_id = "S3-t1-aws-terraform"
    
    forwarded_values {
      query_string = "false"
      
      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "redirect-to-https"
    min_ttl = 0
    default_ttl = 3600
    max_ttl = 86400
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = "true"
  }
}
```

<br>

<p>As soon as <b>CloudFront Distribution</b> is set up, <b>null_resource</b> i.e., <b>cloudfront_url_updation</b> under which connection is set up to the EC2 instances which is same as the one created in previous ones , here usage of <b>“remote- exec”</b> provisioner is done but for different purpose i.e. updation of image source in <b>HTML img tag</b> with the domain_name whose value could be obtained from CloudFront Distribution created using cloudfront_distribution resource .</p>
<p>Updation is performed using <b>“sed”</b> which is a Linux command.</p>

```hcl
resource "null_resource" "cloudfront_url_updation" {
  depends_on = [
    aws_cloudfront_distribution.task_cloudfront_distribution
  ]  
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.tlskey.private_key_pem
    host     = aws_instance.myinstance.public_ip
  }

  provisioner "remote-exec"{
    inline = [
      "sudo sed -ie 's,freddie_mercury.jpg,https://${aws_cloudfront_distribution.task_cloudfront_distribution.domain_name}/freddie_mercury.jpg,g' /var/www/html/index.html"
    ]
  }
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>EBS Snapshot</b> is a point-in-time copy of <b>EBS Volume</b> and are incremental copies of data and could be generated using Terraform resource known as <b>aws_ebs_snapshot</b> and it depends on the complete execution of null_resource i.e., cloudfront_url_updation and the required parameter is <b>volume_id</b> whose value could be obtained from aws_ebs_volume resource.</p><br>

```hcl
resource "aws_ebs_snapshot" "task_snapshot" {
   depends_on = [
    null_resource.cloudfront_url_updation
  ]
  volume_id = aws_ebs_volume.myebs.id
  
  tags = {
    Name = "Task 1 snapshot"
  }
}
```

<br>

<p align="center"><b>. . .</b></p><br>

<p><b>public_ip</b> generated by aws_instance could be placed as an output so as to access the web page set up inside EC2 Instance by using <b>output</b> command in Terraform and it depends on execution of aws_ebs_snapshot resource.</p><br>

```hcl
output "instance_public_ip" {
  depends_on = [
     aws_ebs_snapshot.task_snapshot
  ]
  value = aws_instance.myinstance.public_ip
}
```

<br><br>

<h2>Part 2 : Integration with Jenkins</h2>

<h3>Job 1 : Generation of Public URL using ngrok</h3>

<p>First of all set up ngrok which uses the concept of tunneling providing Public URL, the command to activate ngrok is as follows</p><br>
<p><b>./ngrok http 8080</b></p><br>
<p>Here , the port number specified i.e., <b>8080</b> is the default port number for <b>Jenkins</b>.</p>

![ngrok](https://miro.medium.com/max/875/1*72KcjdsWyRi3fkbsElkJ4Q.png)

<br><br>
<h3>Job 2 : Setting up Webhook in GitHub</h3>

<p>First, select the repository and then select <b>Settings</b> on right hand corner.</p>

![webhook_1](https://miro.medium.com/max/875/1*loo-FxE7l4XBb7pP9oE-SA.png)

<br>
<p>Then , select <b>Webhooks</b> from the list of options present on the left hand side.</p>

![webhook_2](https://miro.medium.com/max/875/1*oOc21axSnjcTjQnU5k3H2A.png)

<br>
<p>Then click on <b>Add Webhook</b> on the top right .</p>

![webhook_3](https://miro.medium.com/max/875/1*8SLK0KIvEoXtPKMinyAjLw.png)

<br>
<p>Then in <b>Payload URL</b>, specify the URL in the format <b>“generatedURL/github-webhook/”</b> and under <b>Current type</b> , select <b>“application/json”</b>.</p>

![webhook_4](https://miro.medium.com/max/875/1*Op_u8C_S30dZ2ifHwIrmrQ.png)<br>

<p>Hence , the Webhook setup in GitHub has been done successfully</p><br><br>

<h3>Job 3 : Setting up Jenkins</h3>

<p>In the command line , the command for enabling Jenkins are as follows</p><br>
<p><b>systemctl start jenkins</b></p><br>
<p>Then , using <b>ifconfig</b> command, find the IP Address respective to the Network Card of your system.</p>
<p>After which, specify the IP address along with Port Number <b>8080</b> i.e., default port number for Jenkins and then this screen would appear .</p>

![Jenkins](https://miro.medium.com/max/875/1*gjmLcaXCTg5bJaXnKh271g.png)

<br>
<p>Enter Jenkins using the respective <b>Username</b> and <b>Password</b>.</p>
<p>Select on <b>“New item”</b></p>

![Jenkins_1](https://miro.medium.com/max/875/1*2-IIUiq_ou65WsO3F3W4Tg.png)

<br>
<p>Enter the name of the Job and click on <b>“Freestyle project”</b>, then click <b>OK</b>.</p>

![Jenkins_2](https://miro.medium.com/max/875/1*3FNhqqbTl3zcyuMhgGTS0Q.png)

<br><br>

<h3>Job 4 : Jenkins Job Setup</h3>
<p>For setting up Jenkins with GitHub , place the URL of the respective repository under <b>“Repository URL”</b> section of <b>Git</b> under <b>Source Code Management</b>.</p>
<p>For setting up <b>Build Trigger</b> to the Webhook that was setup before , click on <b>“GitHub hook trigger for GITScm polling”</b> .</p>

![Jenkins_3](https://miro.medium.com/max/875/1*c-Mp7c1XaqwgMU0JzcVM3A.png)

<br>
<p>Under <b>Build</b>, select <b>“Execute shell”</b></p>

![Jenkins_4](https://miro.medium.com/max/875/1*6otHDI0w_OrIe_e2H5rZnA.png)

<br>
<p>Then , add the code for setting up CI/CD Pipeline of AWS and Terraform with Jenkins .</p>

```shell
/usr/local/bin/aws configure set aws_access_key_id *******************
/usr/local/bin/aws configure set aws_secret_access_key ************************
/usr/local/bin/terraform destroy -auto-approve -lock=false -input=false
/usr/local/bin/terraform init -input=false
/usr/local/bin/terraform destroy -auto-approve -lock=false -input=false
/usr/local/bin/terraform plan -input=false -lock=false  -parallelism=1
/usr/local/bin/terraform apply -auto-approve -lock=false -input=false  -parallelism=1
/usr/local/bin/terraform destroy -auto-approve -lock=false -input=false
```

<p><b>terraform init</b> installs the required plugins to build the infrastructure</p>
<p><b>terraform plan</b> provides the order in which execution would be done</p>
<p><b>terraform apply</b> sets up the complete infrastructure</p>
<p><b>terraform destroy</b> destroys the complete infrastructure</p>
<p><b>aws configure set</b> is used for setting up security credentials</p>

<h2>Note</h2>
<p>To learn how to create an GitHub <b>OAuth Token</b> , check this link</p>
https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line

<br>
<p><b>depends_on</b> is used in Terraform as execution in Terraform doesn’t takes place in sequential manner , it would create problem in setting up infrastructure if resource dependent on other resources is executed first and many more cases so as to maintain a proper order of execution, it is used.</p><br>

<p><b>tags</b> are used in Terraform for defining key and values and associating it with the resources.</p><br><br>

<h2>Thank You :smiley:<h2>
<h3>LinkedIn Profile</h3>
https://www.linkedin.com/in/satyam-singh-95a266182

<h2>Link to the repository mentioned above</h2>
https://github.com/satyamcs1999/terraform_aws_jenkins.git
