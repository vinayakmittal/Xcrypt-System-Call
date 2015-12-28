#include <asm/uaccess.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include "sys_xcrypt.h"


//Defined macros for variables often used in program.
#define MAX_FILE_PATH 254
#define MD5_KEY_SIZE 16
#define ENC_ALGO_TYPE "ctr(aes)"
#define DO_ENCRYPT 1
#define DO_DECRYPT 0

// Function pointer which links to system call.
asmlinkage extern long (*sysptr)(void *arg);

/*
Function:validateInput function takes the void * argument and check for the authencity of the arguments passed 
from the user space. If any error occurs, it returns a proper error status or else returns 0.
*/
long validateInput(void *arg)
{
	sysargs *ptr = (sysargs *) arg;

	long err=0;
	
	//Checking validity of user pointer.
	if(ptr == NULL || unlikely(!access_ok(VERIFY_READ,ptr,sizeof(sysargs))))
	{
        	err = -EFAULT;
		goto exit_point;
	}

	//Checking validity of input file name.
	if(ptr->input_file == NULL || unlikely(!access_ok(VERIFY_READ,ptr->input_file,sizeof(ptr->input_file))))
	{
		err = -EFAULT;
		goto exit_point;
	}

	//Checking validity of output file name.
	if(ptr->output_file == NULL || unlikely(!access_ok(VERIFY_READ,ptr->output_file,sizeof(ptr->output_file))))
	{
                err = -EFAULT;
		goto exit_point;
	}

	//Checking validity of key length.
	if(ptr->key_buffer == NULL || unlikely(!access_ok(VERIFY_READ,ptr->key_buffer,ptr->keylength)))
	{
		err = -EFAULT;
		goto exit_point;
	}

	//Checking if file name exceeds the permissible file name length.
	if(strlen(ptr->input_file)> MAX_FILE_PATH || strlen(ptr->output_file)> MAX_FILE_PATH)
	{
		err = -ENAMETOOLONG;
		goto exit_point;
	}			

	//Checking if keybuffer is within permissible range
	if((strlen(ptr->key_buffer) < MD5_KEY_SIZE ) || (strlen(ptr->key_buffer) > PAGE_SIZE))
	{
		err = -EMSGSIZE;
		goto exit_point;
	}
		
	//Exit Point of function.
	exit_point:
		return err;
}

/*
Function: transferData is used to copy user level arguments to kernel level arguments. 
It first assigns the memory for kernel arguments and then copies the data from user arguments.
*/
long transferData(sysargs *src,sysargs *dest)
{
	long err=0;
	int cpy=0;

	//Allocates memory for input file.
	dest->input_file = kmalloc(strlen(src->input_file)+1, GFP_KERNEL);
	if (dest->input_file == NULL)
	{
		err = -ENOMEM;
		goto free_infile_mem;
	}
	
	//Copies input file name from user to kernel space.
	cpy = copy_from_user(dest->input_file, src->input_file, strlen(src->input_file));
	if (cpy != 0)
		goto free_infile_mem;
	
	// Null terminates the input file name.
	dest->input_file[strlen(src->input_file)] = '\0';

	//Allocates memory for output file.
	dest->output_file = kmalloc(strlen(src->output_file)+1, GFP_KERNEL);
	if(dest->output_file == NULL)
	{
		err = -ENOMEM;
		goto free_outfile_mem;
	}

	//Copies output file name from user to kernel space.
	cpy = copy_from_user(dest->output_file, src->output_file, strlen(src->output_file));
	if (cpy != 0)
		goto free_outfile_mem;

	// Null terminates the output file name.
	dest->output_file[strlen(src->output_file)] = '\0';
	
	//Allocates memory for key buffer.
	dest->key_buffer = kmalloc(strlen(src->key_buffer)+1, GFP_KERNEL);
	if (dest->key_buffer == NULL)
	{
		err = -ENOMEM;
		goto free_key_buf;
	}

	//Copies key buffer from user to kernel space.
	cpy = copy_from_user(dest->key_buffer, src->key_buffer, strlen(src->key_buffer));
	if (cpy != 0)
		goto free_key_buf;

	// Null terminates the key buffer name.
	dest->key_buffer[strlen(src->key_buffer)] = '\0';

	//Copies keylength name from user to kernel space.
	cpy = copy_from_user(&dest->keylength, &src->keylength , sizeof(int));
	if (cpy != 0)
		goto set_error;
	
	//Copies flag from user to kernel space.
	cpy = copy_from_user(&dest->flags, &src->flags, sizeof(int));
	if (cpy != 0)
		goto set_error;
	
	return err;

	//Exit Point of function.
	set_error:
		err = cpy;
	free_key_buf:
		kfree(dest->key_buffer);
	free_outfile_mem:
		kfree(dest->output_file);
	free_infile_mem:
		kfree(dest->input_file);

	return err;
}


/*
This function is copied from linux crypto.c file. I have renamed and modified it according to the usage of CTR encryption.
Function: crypto_aes_encrypt does encryption for the data specified by the user in the arguments to the size given and 
returns it in designated output buffer. MD5 key is used to encrypt the data securely. The function invokes
Crypto API method crypto_blkcipher_encrypt. 
This function deploys AES encryption in CTR mode thereby avoiding need for padding.
sg_in and sg_out is declared for input and output buffers, tfm object is instantiated and algo type is defined for 
encryption purpose. Then, scatterlist tables are populated and encrypt method is invoked.
*/
static int crypto_aes_encrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{	
        struct scatterlist sg_in[1], sg_out[1]; //scatter list declaration for input and output buffers.
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(ENC_ALGO_TYPE, 0, CRYPTO_ALG_ASYNC); //Initialising tfm object
        struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 }; 
        int ret; 
        void *iv; 
        int ivsize; 
        char *aes_iv = "abcdefghijklmnop"; //Initialising IV vector

        if (IS_ERR(tfm))
                return PTR_ERR(tfm);

        //Setting init table for input buffer
        sg_init_table(sg_in, 1);
        sg_set_buf(&sg_in[0], src, src_len);
        
        //Setting init table for output buffer
        sg_init_table(sg_out, 1);
        sg_set_buf(sg_out, dst, *dst_len);
        
        //Setting cipher key for encrypt
        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        iv = crypto_blkcipher_crt(tfm)->iv;
        ivsize = crypto_blkcipher_ivsize(tfm);
        
        memcpy(iv, aes_iv, ivsize);

        //Invoking encrypt method for CTR(AES) encryption.
        ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, src_len);
        if (ret < 0) {
                pr_err("crypto_aes_encrypt failed %d\n", ret);                
        }

        crypto_free_blkcipher(tfm);
        return ret;
}


/*
This function is copied from linux crypto.c file. I have renamed and modified it according to the usage of CTR decryption.
Function: crypto_aes_decrypt does decryption for the data specified by the user in the arguments to the size given and 
returns it in designated output buffer. MD5 key is used to encrypt the data securely. The function invokes
Crypto API method crypto_blkcipher_decrypt. 
This function deploys AES decryption in CTR mode thereby avoiding need for padding.
sg_in and sg_out is declared for input and output buffers, tfm object is instantiated and algo type is defined for 
decryption purpose. Then, scatterlist tables are populated and decrypt method is invoked.
*/
static int crypto_aes_decrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{        
        struct scatterlist sg_out[1], sg_in[1]; //scatter list declaration for input and output buffers.
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(ENC_ALGO_TYPE, 0, CRYPTO_ALG_ASYNC); //Initialising tfm object
        struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
        
        char *aes_iv = "abcdefghijklmnop"; //Initialising IV vector

        void *iv;
        int ivsize;
        int ret;        

        if (IS_ERR(tfm))
                return PTR_ERR(tfm);

        //Setting init table for output buffer
        sg_init_table(sg_out, 1);
        sg_set_buf(&sg_out[0], dst, *dst_len);

        //Setting init table for input buffer
        sg_init_table(sg_in, 1);
        sg_set_buf(sg_in, src, src_len);               

        //Setting cipher key for decrypt
        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        iv = crypto_blkcipher_crt(tfm)->iv;
        ivsize = crypto_blkcipher_ivsize(tfm);
        memcpy(iv, aes_iv, ivsize);

        //Invoking decrypt method for CTR(AES) decryption.
        ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
        if (ret < 0) {
                pr_err("crypto_aes_decrypt failed %d\n", ret);                
        }
        
        crypto_free_blkcipher(tfm);
        return ret;
}

/*
This function is copied from ecryptfs/crypto.c. 
Function:generate_md5 is renamed and modified according to the usage.
This function takes destination, source and key length. It initialises the desc and hashing type.
And then does init, update and final for crypto_hash. And finally generates the md5 key.
*/
static int generate_md5(char *dst, char *src, int len)                                                            
{
        struct scatterlist sg; //Declaring scatter list.
        struct hash_desc desc = {
                .tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC),  //Allocating tfm object for md5 hash                                          
                .flags = CRYPTO_TFM_REQ_MAY_SLEEP 
        };

        int rc = 0;
        
        //Initialising buffer for md5.
        sg_init_one(&sg, (u8 *)src, len);       
        
        if (IS_ERR(desc.tfm)) 
        {
            rc = PTR_ERR(desc.tfm);
            printk("Error attempting to allocate crypto context; rc = [%d]\n", rc);
            goto out;
        }                
        
        //Initializing crypto hash
        rc = crypto_hash_init(&desc);
        if (rc) {
                printk("%s: Error initializing crypto hash; rc = [%d]\n", __func__, rc);
                goto out;
        }

        //Updating crypto hash
        rc = crypto_hash_update(&desc, &sg, len);
        if (rc) {
                printk("%s: Error updating crypto hash; rc = [%d]\n", __func__, rc);
                goto out;
        }

        //Finalizing crypto hash
        rc = crypto_hash_final(&desc, dst);
        if (rc) {
                printk("%s: Error finalizing crypto hash; rc = [%d]\n", __func__, rc);
                goto out;
        }
	
	out:        
        return rc;
}

/*
Function: perform_xcrypt takes the struct of kernel arguments and first generates the md5 hash of the hashed key
provided from user space to provide more security. Then, it first opens the input file, output file and temp file 
handlers for reading/writing purposes. Based on encryption/decryption need of the user, it requests the encrypt/decrypt 
method to perform the operation. 
On the successful execution of the program, .tmp file is renamed to output. Otherwise, .tmp file is deleted.
In case of any errors, returns a proper error message.
*/
long perform_xcrypt(sysargs *k_arg)
{
	//Variable declarations for storing return message, md5 hash and file handlers.
	long rNo = 0, rc = 0;	
	char *rBuf, *wBuf, *ext = ".tmp";
	int rByte=0 , wByte=0 , flag, isFileToCreate=0;
	struct file *infile, *outfile, *temp;
	char *tmpFile;
	struct dentry *tmpfile_dentry, *outfile_dentry;	
	unsigned char *md5_final = NULL;
	mm_segment_t old_fs;	
	
	//Allocating buffer for md5 key
	md5_final = kmalloc(MD5_KEY_SIZE, GFP_KERNEL);

	if(md5_final == NULL)
	{
		rNo = -ENOMEM;
		goto exit_point;
	}

	memset(md5_final, 0, MD5_KEY_SIZE);

	//Calling MD5 generation function
	rc = generate_md5((char *)md5_final, k_arg->key_buffer, k_arg->keylength);

	if(rc < 0)
	{
		rNo = rc;
		goto md5_final_fail;
	}

	// Allocating memory for read buffer.
	rBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if(rBuf ==  NULL)	
	{
		rNo = -ENOMEM;
		goto md5_final_fail;
	}

	memset(rBuf, 0, PAGE_SIZE);

	//Allocating memory for write buffer.
	wBuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(wBuf == NULL)
	{
		rNo = -ENOMEM;
		goto free_read_buf;
	}

	memset(wBuf, 0, PAGE_SIZE);	

	//Opening file handler for input file.
	infile = filp_open(k_arg->input_file, O_RDONLY, 0);

	if(!infile || IS_ERR(infile))
	{
		rNo = -ENOENT;
		goto free_write_buf;
	}

	if(!infile->f_op->read)
	{
		rNo = -EIO;
		goto infile_err;
	}

	//Checking if the input file is a regular file and not a directory.
	if(!S_ISREG(infile->f_path.dentry->d_inode->i_mode))
	{
		rNo = -EBADF;
		goto infile_err;			
	}

	//Checking if the output file exists in the system.
	outfile = filp_open(k_arg->output_file, O_RDONLY, 0);

	if(!outfile || IS_ERR(outfile))	
		isFileToCreate = 1;	

	//Opening file handler for output file.
	outfile = filp_open(k_arg->output_file, O_CREAT|O_WRONLY, infile->f_mode);
	
	if(!outfile || IS_ERR(outfile))
	{
		rNo = -ENOENT;
		goto infile_err;
	}

	//Checking if both input and output files exist on the same partition and their inode numbers are also same.
	if((infile->f_path.dentry->d_inode->i_sb == outfile->f_path.dentry->d_inode->i_sb) && 
		(infile->f_path.dentry->d_inode->i_ino ==  outfile->f_path.dentry->d_inode->i_ino)) 
	{		
		rNo = -EINVAL;
		goto outfile_err;
	}

	if(!outfile->f_op->write)
	{
		rNo = -EROFS;
		goto outfile_err;		
	}				
	
	//Initiating process for storing file name for temporary file name <output_file_name>.tmp
	tmpFile = kmalloc(strlen(k_arg->output_file)+5, GFP_KERNEL);

	if(!tmpFile)
	{
		rNo = -ENOMEM;
		goto outfile_err;
	}

	memset(tmpFile, 0, strlen(k_arg->output_file)+5);
	memcpy(tmpFile, k_arg->output_file, strlen(k_arg->output_file));
	memcpy(tmpFile+strlen(k_arg->output_file), ext, 4);
	tmpFile[strlen(k_arg->output_file)+4] = '\0';

	//Opening file handler for temp file.
	temp= filp_open(tmpFile, O_CREAT|O_WRONLY, infile->f_mode);
	if(!temp || IS_ERR(temp))
	{
		rNo = -ENOENT;
		goto free_temp_file;
	}

	if(!temp->f_op->write)
	{
		rNo = -EROFS;
		goto temp_file_err;		
	}	

	//Setting same file modes to temp file as of input file specified.
	temp->f_path.dentry->d_inode->i_mode = infile->f_path.dentry->d_inode->i_mode;
	temp->f_path.dentry->d_inode->i_opflags = infile->f_path.dentry->d_inode->i_opflags;
	temp->f_path.dentry->d_inode->i_uid = infile->f_path.dentry->d_inode->i_uid;
	temp->f_path.dentry->d_inode->i_gid = infile->f_path.dentry->d_inode->i_gid;
	temp->f_path.dentry->d_inode->i_flags = infile->f_path.dentry->d_inode->i_flags;

	outfile_dentry = outfile->f_path.dentry;
	tmpfile_dentry = temp->f_path.dentry;
	
	//Initializing input and temp file offsets to zero for reading and writing.	
	infile->f_pos = 0;
	temp->f_pos = 0;	

	flag = k_arg->flags & 1;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if(flag == DO_ENCRYPT) // Executes if encryption is to de done.
	{		
		// Writing hashed MD5 key into premable of temp file.			
		wByte = vfs_write(temp, md5_final, MD5_KEY_SIZE, &temp->f_pos);		

		if(wByte < 0)
		{
			rNo = -EIO;
			goto xcrypt_err;
		}

		//Reading input from file into PAGE_SIZE and writing it to temp file after encryption.
		while((rByte = vfs_read(infile, rBuf, PAGE_SIZE, &infile->f_pos)) > 0)	
		{								
			//Calling Encrypt method 			
			crypto_aes_encrypt(k_arg->key_buffer, MD5_KEY_SIZE, wBuf, &rByte, rBuf, rByte);
			wByte = vfs_write(temp, wBuf, rByte, &temp->f_pos);

			if(wByte < rByte)
			{
				rNo = -EIO;
				goto xcrypt_err;	
			}			
		}

		if(rByte < 0)
		{
			rNo = -EIO;
			goto xcrypt_err;
		}		
	}
	else if(flag == DO_DECRYPT) // Executes if decryption is to be done.
	{
		//Reading hashed MD5 key from input file to validate the key.
		rByte = vfs_read(infile, rBuf, MD5_KEY_SIZE, &infile->f_pos);		

		if(rByte < 0)
		{
			rNo = -EIO;
			goto xcrypt_err;
		}

		if (memcmp(rBuf, md5_final, MD5_KEY_SIZE) == 0) //Validating file key and user key.
		{			
			//Reading from input file into PAGE_SIZE, decrypts it and store it to temp file.
			while((rByte = vfs_read(infile, rBuf, PAGE_SIZE, &infile->f_pos)) > 0)
			{								
				//Calling Decrypt method 										
				crypto_aes_decrypt(k_arg->key_buffer, MD5_KEY_SIZE, wBuf, &rByte, rBuf, rByte);
				wByte = vfs_write(temp, wBuf, rByte, &temp->f_pos);

				if(wByte < rByte)
				{
					rNo = -EIO;
					goto xcrypt_err;	
				}		
			}

			if(rByte < 0)
			{
				rNo = -EIO;
				goto xcrypt_err;
			}				
		}
		else //Executes if invalid key is specified.
		{			
			rNo = -EPERM;
			goto xcrypt_err;
		}			
	}
	else //Executes if wrong flag is provided for encryption/decryption.
	{
		rNo = -EINVAL;
		goto xcrypt_err;
	}
	
	//Renaming temp file to output file.
	vfs_rename(tmpfile_dentry->d_parent->d_inode, tmpfile_dentry, outfile_dentry->d_parent->d_inode, outfile_dentry, NULL, 0);		

	//Exit Point of function.
	xcrypt_err:
		if(rNo < 0)
			vfs_unlink(tmpfile_dentry->d_parent->d_inode, tmpfile_dentry, NULL); //Deleting temp file.
		if(isFileToCreate == 1)		
			vfs_unlink(outfile_dentry->d_parent->d_inode, outfile_dentry, NULL); //Deleting partial output file.

		set_fs(old_fs);
		
	temp_file_err:
		filp_close(temp, NULL);
	free_temp_file:
		kfree(tmpFile);
	outfile_err:
		filp_close(outfile, NULL);
	infile_err:
		filp_close(infile, NULL);
	free_write_buf:
		kfree(wBuf);
	free_read_buf:
		kfree(rBuf);
	md5_final_fail:
		kfree(md5_final);
	exit_point:
		return rNo;	
}

asmlinkage long xcrypt(void *arg)
{
	//Variable declarations for kernel arguments.
	sysargs *k_arg = NULL;
	long rNo=0;		

	//Checks for validity of the user arguments.
	long isValid = validateInput(arg);	

	if(isValid < 0)
	{
		rNo = isValid;
		goto invalid_input;
	}
	
	k_arg = kmalloc(sizeof(sysargs),GFP_KERNEL);
	if(!k_arg)
	{
		rNo = -ENOMEM;
		goto mem_fail;	
	}
		
	//Copies data to kernel space from user space.
	rNo = transferData(arg, k_arg);
	if(rNo < 0)
		goto mem_fail;				
	
	rNo = perform_xcrypt(k_arg);

	//Exit Point of function.
	mem_fail:
		kfree(k_arg);
	invalid_input:
		return rNo;
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}

module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("VINAYAK MITTAL");
MODULE_DESCRIPTION("XCrypt System Call: Encrypts/Decrypts file");
