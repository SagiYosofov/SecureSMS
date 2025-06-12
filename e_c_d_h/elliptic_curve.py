import galois


class EllipticCurve(object):

    def __init__(self, a, b):
        # assume we're already in the Weierstrass form
        self.a = a
        self.b = b

        self.discriminant = -16 * (4 * a * a * a + 27 * b * b)
        if not self.isSmooth():
            raise Exception("The curve %s is not smooth!" % self)

    def isSmooth(self):
        """
            Check whether the elliptic curve is smooth (i.e., has no singularities). slide 9 in elliptic curve lecture.

            A smooth elliptic curve must have a non-zero discriminant. This method
            evaluates the discriminant of the curve and returns True if it is non-zero,
            indicating that the curve is smooth.

            Returns:
                bool: True if the curve is smooth (discriminant ≠ 0), False otherwise.
        """
        return self.discriminant != 0

    def testPoint(self, x, y):
        '''check if the given point is on the elliptic curve'''
        return y * y == x * x * x + self.a * x + self.b

    def __str__(self):
        return 'y^2 = x^3 + %sx + %s' % (self.a, self.b)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        """
        This method allows you to use the == operator to compare two EllipticCurve instances.
        """
        return (self.a, self.b) == (other.a, other.b)

    def findPoints(self, field: galois._fields._meta.FieldArrayMeta):
        print(f'Finding all points over {self}')
        print(f'Total number of field elements: {field.order}')

        points = []

        # Loop over all x, y in the field (brute-force)
        for x in field.elements:
            for y in field.elements:
                if self.testPoint(x, y):
                    points.append(Point(self, x, y))

        return points


class Point(object):
    def __init__(self, curve, x, y):
        self.curve = curve  # the curve containing this point
        self.x = x
        self.y = y

        if not curve.testPoint(x, y):
            raise Exception("The point %s is not on the given curve %s!" % (self, curve))


    def slowOrder(self):
        Q = self
        i = 1
        while True:
            if type(Q) is Ideal:
                return i
            else:
                Q = Q + self
                i += 1

    def __str__(self):
        return "(%r, %r)" % (self.x, self.y)

    def __repr__(self):
        return str(self)

    def __neg__(self):
        """
            Return the negation of a point on the elliptic curve.

            In elliptic curve arithmetic, the negation of a point \( P = (x, y) \) is
            defined as \( -P = (x, -y) \). This operation reflects the point across the
            x-axis and is essential for defining point subtraction and the group inverse.

            Returns:
                Point: A new Point instance representing the negation of the current point.
        """
        return Point(self.curve, self.x, -self.y)

    def __add__(self, Q):
        # check that both points belong to the same elliptic curve.
        if self.curve != Q.curve:
            raise Exception("Can't add points on different curves!")

        # This checks if Q is the point at infinity (called Ideal here), which is the identity element of the group.
        # P+O = O+P = P for every P belongs to E
        if isinstance(Q, Ideal):
            return self

        x_1, y_1, x_2, y_2 = self.x, self.y, Q.x, Q.y
        x_3 = None
        y_3 = None

        # Case 1
        if x_1 != x_2:
            m = (y_2 - y_1) / (x_2 - x_1)
            x_3 = m ** 2 - x_1 - x_2
            y_3 = m * (x_1 - x_3) - y_1

        # Case 2
        elif x_1 == x_2 and y_1 == -y_2:
            return Ideal(self.curve)

        # Case 3
        elif (x_1, y_1) == (x_2, y_2):
            if y_1 == 0:  # avoid 0 division.
                return Ideal(self.curve)

            m = (3 * x_1 ** 2 + self.curve.a) / (2 * y_1)

            x_3 = m * m - x_1 - x_2
            y_3 = m * (x_1 - x_3) - y_1

        return Point(self.curve, x_3, -y_3)

    def __sub__(self, Q):
        return self + -Q

    def __mul__(self, n: int):
        if not isinstance(n, int):
            raise Exception("Can't scale a point by something which isn't an int!")
        else:
            if n < 0:
                # recursion call
                return -self * -n
            if n == 0:
                return Ideal(self.curve)
            else:
                Q = Ideal(self.curve)
                base = self
                # n*Q = (Q+Q+Q+ .. +Q) n times
                for i in range(n):
                    Q = Q + base
                return Q

    def __rmul__(self, n):
        return self * n

    def __list__(self):
        return [self.x, self.y]

    def __eq__(self, other):
        if type(other) is Ideal:
            return False

        return (self.x, self.y) == (other.x, other.y)

    def __ne__(self, other):
        return not self == other

    def __getitem__(self, index):
        return [self.x, self.y][index]


class Ideal:
    def __init__(self, curve):
        self.curve = curve

    def __neg__(self):
        return self

    def __str__(self):
        return "Ideal"

    def __add__(self, Q):
        if self.curve != Q.curve:
            raise Exception("Can't add points on different curves!")
        return Q

    def __mul__(self, n):
        if not isinstance(n, int):
            raise Exception("Can't scale a point by something which isn't an int!")
        else:
            return self

    def __eq__(self, other):
        return type(other) is Ideal
