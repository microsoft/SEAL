using System;
using System.Collections.Generic;

namespace Encounter
{
    // Yoink: https://rosettacode.org/wiki/Parsing/RPN_calculator_algorithm#C.23
    public class ReversePolishNotationParser
    {
        static decimal CalculateRPN(string rpn)
        {
            string[] rpnTokens = rpn.Split(' ');
            Stack<decimal> stack = new Stack<decimal>();
            decimal number = decimal.Zero;

            foreach (string token in rpnTokens)
            {
                if (decimal.TryParse(token, out number))
                {
                    stack.Push(number);
                }
                else
                {
                    switch (token)
                    {
                        case "^":
                        case "pow":
                            number = stack.Pop();
                            stack.Push((decimal)Math.Pow((double)stack.Pop(), (double)number));
                            break;
                        case "*":
                            stack.Push(stack.Pop() * stack.Pop());
                            break;
                        case "/":
                            number = stack.Pop();
                            stack.Push(stack.Pop() / number);
                            break;
                        case "+":
                            stack.Push(stack.Pop() + stack.Pop());
                            break;
                        case "-":
                            number = stack.Pop();
                            stack.Push(stack.Pop() - number);
                            break;
                        default:
                            Console.WriteLine("Error in CalculateRPN(string) Method!");
                            break;
                    }
                }
            }
            return stack.Pop();
        }
    }
}
