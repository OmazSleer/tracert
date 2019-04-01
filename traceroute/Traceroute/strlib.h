#ifndef _STRLIB_H
#define _STRLIB_H

//����� ��������� ��� ������������, ���� ������ �������������
//msg - ��������� ������������, Length - ������������ ����� ������
char *str_input(const char msg[], int Length);

#define LeftSide 0
#define RightSide 1
//���������� ����� ������ str ��/����� ������� ind
//side - �������� �� ����������� �� ind 
//LeftSide - ��� ������ ����� �� ind 
//RightSide - ��� ������ ������ �� ind
char *str_part(char *str, const int ind, const int side);

//�������� numb ��������� �� ������ str � ������� pos 
void str_delete(char **str, const int pos, const unsigned int numb);

//�������� ���� �������� �� ������ str
void str_delete_spa�e(char *str);

#endif // !_STRLIB_H

