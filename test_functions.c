#include<stdio.h>
#include<stdlib.h>
#include<string.h>

// Vulnerable Test function
int vulnfunc(char * test){

	char vulnstr[16];
	strcpy(vulnstr, test); // Vulnerability is here
	if(strcmp(vulnstr, "hello"))
		return 0;
	return 1;
}

int main(int argc, char * argv[]) {

	// check for input
	if( argc != 2) {
		printf("Two args are required\n");
		return 1;
	}

	// call vulnerable function
	if(vulnfunc(argv[1])) {
		printf("fail\n");
	} else {
		printf("success\n");
	}

	// Other functions to test to ensure working program
	puts(argv[1]);
	printf("%d", (int)strlen(argv[1]));
	printf("%d", atoi(argv[1]));
	printf("%f", atof(argv[1]));
	printf("%ld", atol(argv[1]));

	return 0;
}
