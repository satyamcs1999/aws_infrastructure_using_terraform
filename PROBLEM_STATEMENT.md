__<h1>Problem Statement</h1>__

<ul>
  <li>Creation of Key & Security Group(Allows Port 80)</li>
  <li>Creation of EC2 Instance using the Key & Security Group created in the above step</li>
  <li>EBS Volume creation & mounting it to /var/www/html</li>
  <li>Developer uploads code and images into GitHub repository</li>
  <li>Copying code to /var/www/html</li>
  <li>Creation of S3 Bucket</li>
  <li>Deployment of image to the S3 bucket and changing bucket's permission to public readable</li>
  <li>Creation of CloudFront using S3 Bucket and usage of CloudFront URL to update the code in /var/www/html</li>
  <li>Creation of EBS Snapshot</li>
  <li>Integrate Jenkins with the above steps</li>
</ul>
